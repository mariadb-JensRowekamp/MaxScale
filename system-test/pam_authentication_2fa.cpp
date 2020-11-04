/*
 * Copyright (c) 2020 MariaDB Corporation Ab
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file and at www.mariadb.com/bsl11.
 *
 * Change Date: 2024-10-14
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2 or later of the General
 * Public License.
 */

#include <maxtest/testconnections.hh>
#include <maxtest/mariadb_connector.hh>
#include "mariadbmonitor/fail_switch_rejoin_common.cpp"
#include <iostream>
#include <string>
#include <maxbase/format.hh>

using std::string;
using std::cout;
using mxt::ServerInfo;

// Helper function for checking PAM-login. If db is empty, log to null database.
bool test_pam_login(TestConnections& test, int port, const string& user, const string& pass,
                    const string& pass2, const string& database);

string generate_2fa_token(TestConnections& test, const string& secret);

int main(int argc, char** argv)
{
    TestConnections test(argc, argv);
    test.maxscales->ssl = false;
    test.repl->connect();
    delete_slave_binlogs(test);

    const char install_plugin[] = "INSTALL SONAME 'auth_pam';";
    const char uninstall_plugin[] = "UNINSTALL SONAME 'auth_pam';";

    const char pam_user[] = "twofactor_user";
    const char pam_pw[] = "twofactor_pass";
    const char pam_config_name[] = "twofactor_conf";

    const string add_user_cmd = (string)"useradd " + pam_user;
    const string add_pw_cmd = (string)"echo " + pam_user + ":" + pam_pw + " | chpasswd";
    const string read_shadow = "chmod o+r /etc/shadow";

    const string remove_user_cmd = (string)"userdel --remove " + pam_user;
    const string read_shadow_off = "chmod o-r /etc/shadow";

    // To make most out of this test, use a custom pam service configuration. It needs to be written to
    // all backends.

    const string pam_config_file = (string)"/etc/pam.d/" + pam_config_name;

    // Use a somewhat non-standard pam config. Does not affect the validity of the test, as we are not
    // testing the security of the google authenticator itself.
    const string pam_config_contents = R"(
auth            required        pam_unix.so
auth            required        pam_google_authenticator.so nullok no_strict_owner allowed_perm=0777 secret=/tmp/.google_authenticator
account         required        pam_unix.so
)";

    const string gauth_secret_key = "3C7OP37ONKJOELVIMNZ67AADSY";
    const string gauth_keyfile_contents = gauth_secret_key + "\n" +
R"(\" RATE_LIMIT 3 30
\" TOTP_AUTH
74865607
49583434
76566817
48621211
71963974)";
    const string gauth_secret_path = "/tmp/.google_authenticator";

    const string create_pam_conf_cmd = "printf \"" + pam_config_contents + "\" > " + pam_config_file;
    const string delete_pam_conf_cmd = "rm -f " + pam_config_file;

    const string create_2fa_secret_cmd = "printf \"" + gauth_keyfile_contents + "\" > " + gauth_secret_path;
    const string delete_2fa_secret_cmd = "rm -f " + gauth_secret_path;

    const int N = 2;
    auto cleanup = [&]() {
        // Cleanup: remove linux user and files from the MaxScale node.
        test.maxscales->ssh_node_f(0, true, "%s", remove_user_cmd.c_str());
        test.maxscales->ssh_node_f(0, true, "%s", read_shadow_off.c_str());
        test.maxscales->ssh_node_f(0, true, "%s", delete_pam_conf_cmd.c_str());
        test.maxscales->ssh_node_f(0, true, "%s", delete_2fa_secret_cmd.c_str());

        // Cleanup: remove the linux users on the backends, unload pam plugin.
        for (int i = 0; i < N; i++)
        {
            MYSQL* conn = test.repl->nodes[i];
            execute_query(conn, "%s", uninstall_plugin);
            test.repl->ssh_node_f(i, true, "%s", remove_user_cmd.c_str());
            test.repl->ssh_node_f(i, true, "%s", read_shadow_off.c_str());
            test.repl->ssh_node_f(i, true, "%s", delete_pam_conf_cmd.c_str());
            test.repl->ssh_node_f(i, true, "%s", delete_2fa_secret_cmd.c_str());
        }
    };

    auto initialize = [&]() {
        // Setup pam 2fa on the MaxScale node + on two MariaDB-nodes. Quite similar to
        // pam_authentication test.
        for (int i = 0; i < N; i++)
        {
            MYSQL* conn = test.repl->nodes[i];
            test.try_query(conn, "%s", install_plugin);
            test.repl->ssh_node_f(i, true, "%s", add_user_cmd.c_str());
            test.repl->ssh_node_f(i, true, "%s", add_pw_cmd.c_str());
            test.repl->ssh_node_f(i, true, "%s", read_shadow.c_str());
            test.repl->ssh_node_f(i, true, "%s", create_pam_conf_cmd.c_str());
            test.repl->ssh_node_f(i, true, "%s", create_2fa_secret_cmd.c_str());
        }

        // Create the user on the node running MaxScale, as the MaxScale PAM plugin compares against
        // local users.
        test.maxscales->ssh_node_f(0, true, "%s", add_user_cmd.c_str());
        test.maxscales->ssh_node_f(0, true, "%s", add_pw_cmd.c_str());
        test.maxscales->ssh_node_f(0, true, "%s", read_shadow.c_str());
        test.maxscales->ssh_node_f(0, true, "%s", create_pam_conf_cmd.c_str());
        test.maxscales->ssh_node_f(0, true, "%s", create_2fa_secret_cmd.c_str());
    };

    cleanup(); // remove conflicting usernames and files, just in case.
    initialize();

    if (test.ok())
    {
        test.tprintf("PAM-plugin installed and users created on all servers.");
        auto& mxs = test.maxscale();
        auto expected_states = {ServerInfo::master_st, ServerInfo::slave_st};
        mxs.check_servers_status(expected_states);

        if (test.ok())
        {
            const char create_pam_user_fmt[] = "CREATE OR REPLACE USER '%s'@'%%' "
                                               "IDENTIFIED VIA pam USING '%s';";
            auto create_user_query = mxb::string_printf(create_pam_user_fmt, pam_user, pam_config_name);
            auto admin_conn = mxs.open_rwsplit_connection();
            admin_conn->cmd(create_user_query);
            auto grant_query = mxb::string_printf("GRANT SELECT on test.* TO '%s'@'%%';", pam_user);
            admin_conn->cmd(grant_query);

            if (test.ok())
            {
                cout << "PAUSE\n";
                string cmd;
                std::cin >> cmd;
                if (cmd == "exit")
                {
                    return test.global_result;
                }

                auto twofa_token = generate_2fa_token(test, gauth_secret_key);
                if (!twofa_token.empty())
                {
                    auto succ = test_pam_login(test, test.maxscales->port(), pam_user, pam_pw, twofa_token,
                                               "");
                    if (succ)
                    {
                        cout << "JEEEEE\n";
                    }
                }
            }

            auto drop_user_query = mxb::string_printf("DROP USER '%s'@'%%';", pam_user);
            admin_conn->cmd(drop_user_query);
        }
    }
    else
    {
        cout << "Test preparations failed.\n";
    }

    cleanup();
    test.repl->disconnect();
    return test.global_result;
}

// Helper function for checking PAM-login. If db is empty, log to null database.
bool test_pam_login(TestConnections& test, int port, const string& user, const string& pass,
                    const string& pass2, const string& database)
{
    const char* host = test.maxscales->ip4(0);
    const char* db = nullptr;
    if (!database.empty())
    {
        db = database.c_str();
    }

    if (db)
    {
        test.tprintf("Trying to log in to [%s]:%i as %s with database %s.\n", host, port, user.c_str(), db);
    }
    else
    {
        test.tprintf("Trying to log in to [%s]:%i as %s, with passwords '%s' and '%s'.\n",
               host, port, user.c_str(), pass.c_str(), pass2.c_str());
    }

    bool rval = false;
    // Using two passwords is a bit tricky as connector-c does not have a setting for it. Instead, invoke
    // mysql from the commandline.
    auto url = mxb::string_printf("jdbc:mariadb://%s:%i/?user=%s&password=%s&password2=%s",
                                  host, port, user.c_str(), pass.c_str(), pass2.c_str());
    auto java_cmd = mxb::string_printf("java -jar ConnectionTester.jar '%s'", url.c_str());
    auto file = popen(java_cmd.c_str(), "r");
    if (file)
    {
        sleep(2);
        char buffer[10240];
        size_t rsize = sizeof(buffer);
        auto result = (char*)calloc(rsize, sizeof(char));

        while (fgets(buffer, sizeof(buffer), file))
        {
            result = (char*)realloc(result, sizeof(buffer) + rsize);
            rsize += sizeof(buffer);
            strcat(result, buffer);
        }

        int rc = pclose(file);
        if (rc == 0)
        {
            rval = true;
            cout << "Logged in and queried successfully.\n";
        }
        else
        {
            cout << "Login failed \n";
        }
    }
    return rval;
}

string generate_2fa_token(TestConnections& test, const string& secret)
{
    string rval;
    // Use oathtool to generate a time-limited password.
    auto cmd = mxb::string_printf("oathtool -b --totp %s", secret.c_str());
    auto stream = popen(cmd.c_str(), "r"); // can only read from the pipe
    if (stream)
    {
        int n = 100;
        char buf[n];
        memset(buf, 0, n);
        fgets(buf, n - 1, stream);
        int rc = pclose(stream);
        // 2FA tokens are six numbers long.
        int output_len = strlen(buf);
        int token_len = 6;
        if (output_len == token_len + 1)
        {
            rval.assign(buf, buf + token_len);
        }
        else
        {
            test.add_failure("Failed to generate 2FA token. oathtool output: %s", buf);
        }
    }
    return rval;
}

