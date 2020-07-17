/**
 * @file mysqlmon_multimaster.cpp MySQL Monitor Multi-master Test
 * - Configure all servers into a multi-master ring with one slave
 * - check status using 'show servers' and 'show monitor "MySQL Monitor"'
 * - Set nodes 0 and 1 into read-only mode
 * - repeat status check
 * - Configure nodes 1 and 2 (server2 and server3) into a master-master pair, make node 0 a slave of node 1
 * and node 3 a slave of node 2
 * - repeat status check
 * - Set node 1 into read-only mode
 * - repeat status check
 * - Create two distinct groups (server1 and server2 are masters for eache others and same for server3 and
 * server4)
 * - repeat status check
 * - Set nodes 1 and 3 (server2 and server4) into read-only mode
 *
 * Addition: add delays to some slave connections and check that the monitor correctly detects the delay
 */


#include <string>
#include <maxtest/testconnections.hh>

using std::string;
using std::vector;

void
check_rlag(TestConnections& test, const ServersInfo& servers_info, size_t ind, int min_rlag, int max_rlag);

void change_master(TestConnections& test, int slave, int master, const string& conn_name = "",
                   int replication_delay = 0);

int main(int argc, char* argv[])
{
    auto mm_master_status = ServerInfo::MASTER | ServerInfo::RUNNING;
    auto mm_slave_status = ServerInfo::RELAY | ServerInfo::SLAVE | ServerInfo::RUNNING;
    auto slave_status = ServerInfo::SLAVE | ServerInfo::RUNNING;
    auto running_status = ServerInfo::RUNNING;
    auto grp_none = ServerInfo::GROUP_NONE;

    const char reset_query[] = "STOP SLAVE; RESET SLAVE ALL; RESET MASTER; SET GLOBAL read_only='OFF'";
    const char readonly_on_query[] = "SET GLOBAL read_only='ON'";

    TestConnections::require_repl_version("10.2.3");    // Delayed replication needs this.
    TestConnections test(argc, argv);

    test.tprintf("Test 1 - Configure all servers into a multi-master ring with one slave");
    int max_rlag = 100;
    test.set_timeout(120);
    test.repl->execute_query_all_nodes(reset_query);
    test.repl->connect();
    change_master(test, 0, 1);
    change_master(test, 1, 2);
    change_master(test, 2, 0);
    change_master(test, 3, 2, "", max_rlag);

    test.maxscale()->wait_monitor_ticks(2);
    auto maxconn = test.maxscales->open_rwsplit_connection();
    test.try_query(maxconn, "FLUSH TABLES;");
    test.maxscale()->wait_monitor_ticks(1);

    auto servers_info = test.maxscale()->get_servers();
    auto phase1_2_groups = {1, 1, 1, grp_none};
    servers_info.check_servers_status(test,
                                      {mm_master_status, mm_slave_status, mm_slave_status, slave_status});
    servers_info.check_master_groups(test, phase1_2_groups);
    check_rlag(test, servers_info, 3, 1, max_rlag);

    // Need to send a read query so that rwsplit detects replication lag.
    test.try_query(maxconn, "SHOW DATABASES;");
    mysql_close(maxconn);
    test.log_includes(0, "is excluded from query routing.");

    test.tprintf("Test 2 - Set nodes 0 and 1 into read-only mode");

    test.set_timeout(120);
    execute_query(test.repl->nodes[0], readonly_on_query);
    execute_query(test.repl->nodes[1], readonly_on_query);
    test.maxscale()->wait_monitor_ticks(1);

    servers_info = test.maxscale()->get_servers();
    servers_info.check_servers_status(test, {mm_slave_status, mm_slave_status, mm_master_status,
                                             slave_status});
    servers_info.check_master_groups(test, phase1_2_groups);
    check_rlag(test, servers_info, 3, 1, max_rlag);

    test.tprintf("Test 3 - Configure nodes 1 and 2 into a master-master pair, make node 0 "
                 "a slave of node 1 and node 3 a slave of node 2");

    test.maxscales->stop_maxscale();
    test.set_timeout(120);
    test.repl->execute_query_all_nodes(reset_query);
    test.repl->connect();

    change_master(test, 0, 1);
    change_master(test, 1, 2);
    change_master(test, 2, 1, "", max_rlag);
    change_master(test, 3, 2);

    test.maxscales->start_maxscale();
    sleep(2);
    test.maxscale()->wait_monitor_ticks(1);

    maxconn = test.maxscales->open_rwsplit_connection();
    test.try_query(maxconn, "FLUSH TABLES;");
    mysql_close(maxconn);
    test.maxscale()->wait_monitor_ticks(1);

    servers_info = test.maxscale()->get_servers();
    auto phase3_4_groups = {grp_none, 1, 1, grp_none};
    servers_info.check_servers_status(test, {slave_status, mm_master_status, mm_slave_status, slave_status});
    servers_info.check_master_groups(test, phase3_4_groups);
    check_rlag(test, servers_info, 2, 1, max_rlag);

    test.tprintf("Test 4 - Set node 1 into read-only mode");

    test.set_timeout(120);
    execute_query(test.repl->nodes[1], readonly_on_query);
    test.maxscale()->wait_monitor_ticks(1);

    servers_info = test.maxscale()->get_servers();
    servers_info.check_servers_status(test, {slave_status, mm_slave_status, mm_master_status, slave_status});
    servers_info.check_master_groups(test, phase3_4_groups);

    test.tprintf("Test 5 - Create two distinct groups");

    test.maxscales->stop_maxscale();
    test.set_timeout(120);
    test.repl->execute_query_all_nodes(reset_query);
    test.repl->connect();

    change_master(test, 0, 1);
    change_master(test, 1, 0);
    change_master(test, 2, 3);
    change_master(test, 3, 2);

    test.maxscales->start_maxscale();
    sleep(2);
    test.maxscale()->wait_monitor_ticks(1);

    // Even though the servers are in two distinct groups, only one of them
    // contains a master and a slave. Only one master may exist in a cluster
    // at once, since by definition this is the server to which routers may
    // direct writes.
    servers_info = test.maxscale()->get_servers();
    auto phase5_6_groups = {1, 1, 2, 2};
    auto phase5_6_status = {mm_master_status, mm_slave_status, running_status, running_status};
    servers_info.check_servers_status(test, phase5_6_status);
    servers_info.check_master_groups(test, phase5_6_groups);

    test.tprintf("Test 6 - Set nodes 1 and 3 into read-only mode");

    test.set_timeout(120);
    execute_query(test.repl->nodes[1], readonly_on_query);
    execute_query(test.repl->nodes[3], readonly_on_query);

    test.maxscale()->wait_monitor_ticks(1);

    servers_info = test.maxscale()->get_servers();
    servers_info.check_servers_status(test, phase5_6_status);
    servers_info.check_master_groups(test, phase5_6_groups);

    test.tprintf("Test 7 - Diamond topology with delay");

    test.repl->execute_query_all_nodes(reset_query);
    test.repl->connect();
    change_master(test, 0, 1, "a", max_rlag);
    change_master(test, 0, 2, "b", max_rlag);
    change_master(test, 1, 3);
    change_master(test, 2, 3);

    test.maxscale()->wait_monitor_ticks(1);
    maxconn = test.maxscales->open_rwsplit_connection();
    test.try_query(maxconn, "FLUSH TABLES;");
    test.maxscale()->wait_monitor_ticks(2);
    test.try_query(maxconn, "SHOW DATABASES;");

    servers_info = test.maxscale()->get_servers();
    auto phase7_8_status = {slave_status, mm_slave_status, mm_slave_status, mm_master_status};
    auto phase7_8_groups = {grp_none, grp_none, grp_none, grp_none};
    servers_info.check_servers_status(test, phase7_8_status);
    servers_info.check_master_groups(test, phase7_8_groups);
    check_rlag(test, servers_info, 0, 1, max_rlag);

    test.tprintf("Test 8 - Diamond topology with no delay");

    const char remove_delay[] = "STOP SLAVE '%s'; CHANGE MASTER '%s' TO master_delay=0; START SLAVE '%s';";
    test.try_query(test.repl->nodes[0], remove_delay, "a", "a", "a");
    test.maxscale()->wait_monitor_ticks(2);

    servers_info = test.maxscale()->get_servers();
    servers_info.check_servers_status(test, phase7_8_status);
    servers_info.check_master_groups(test, phase7_8_groups);
    check_rlag(test, servers_info, 0, 0, 0);

    // Rwsplit should detects that replication lag is 0.
    test.try_query(maxconn, "SHOW DATABASES;");
    mysql_close(maxconn);
    test.log_includes(0, "is returned to query routing.");

    // Test over, reset topology.
    const char reset_with_name[] = "STOP SLAVE '%s'; RESET SLAVE '%s' ALL;";
    test.try_query(test.repl->nodes[0], reset_with_name, "a", "a");
    test.try_query(test.repl->nodes[0], reset_with_name, "b", "b");

    test.repl->execute_query_all_nodes(reset_query);
    test.repl->connect();
    change_master(test, 1, 0);
    change_master(test, 2, 0);
    change_master(test, 3, 0);

    return test.global_result;
}

void
check_rlag(TestConnections& test, const ServersInfo& servers_info, size_t ind, int min_rlag, int max_rlag)
{
    if (ind < servers_info.size())
    {
        auto& srv_info = servers_info.get(ind);
        auto found_rlag = srv_info.rlag;
        if (found_rlag >= min_rlag && found_rlag <= max_rlag)
        {
            test.tprintf("Replication lag of %s is %li seconds.", srv_info.name.c_str(), found_rlag);
        }
        else
        {
            test.add_failure("Replication lag of %s is out of bounds: value: %li min: %i max: %i\n",
                             srv_info.name.c_str(), found_rlag, min_rlag, max_rlag);
        }
    }
}

void
change_master(TestConnections& test, int slave, int master, const string& conn_name, int replication_delay)
{
    const char query[] = "CHANGE MASTER '%s' TO master_host='%s', master_port=%d, "
                         "master_log_file='mar-bin.000001', master_log_pos=4, "
                         "master_user='repl', master_password='repl', master_delay=%d; "
                         "START SLAVE '%s';";
    test.try_query(test.repl->nodes[slave], query, conn_name.c_str(),
                   test.repl->IP_private[master], test.repl->port[master],
                   replication_delay, conn_name.c_str());
}
