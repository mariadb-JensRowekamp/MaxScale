/*
 * Copyright (c) 2020 MariaDB Corporation Ab
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file and at www.mariadb.com/bsl11.
 *
 * Change Date: 2024-07-16
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2 or later of the General
 * Public License.
 */
import { expect } from 'chai'
import mount from '@tests/unit/setup'
import {
    allModulesMap,
    mockupSelection,
    mockupOpenDialog,
    mockupCloseDialog,
    mockupRouteChanges,
} from '@tests/unit/mockup'
import Forms from '@CreateResource/Forms'
import sinon from 'sinon'

/**
 * This function tests whether text is transform correctly based on route changes.
 * It should capitalize first letter of current route name if current page is a dashboard page.
 * For dashboard page, it should also transform plural route name to a singular word,
 * i.e., services become Service
 * @param {Object} wrapper A Wrapper is an object that contains a mounted component and methods to test the component
 * @param {String} path Current route path
 * @param {String} selectedResource Selected resource to be created
 */
async function testingTextTransform(wrapper, path, selectedResource) {
    await mockupRouteChanges(wrapper, path)
    await mockupOpenDialog(wrapper)
    expect(wrapper.vm.$data.selectedResource).to.be.equal(selectedResource)
}

/**
 * This function mockup the selection of resource to be created
 * @param {Object} wrapper A Wrapper is an object that contains a mounted component and methods to test the component
 * @param {String} resourceType resource to be created
 */
async function mockupResourceSelect(wrapper, resourceType) {
    await mockupOpenDialog(wrapper)
    await mockupSelection(wrapper, resourceType, '.resource-select')
}

/**
 * This function test if form dialog is close accurately
 * @param {Object} wrapper A Wrapper is an object that contains a mounted component and methods to test the component
 * @param {String} buttonClass button class: save, cancel, close
 */
async function testCloseModal(wrapper, buttonClass) {
    await mockupResourceSelect(wrapper, 'Server')
    let count = 0
    await wrapper.setProps({
        closeModal: async () => {
            count++
            await wrapper.setProps({ value: false })
        },
    })
    await wrapper.setData({
        resourceId: 'test-server',
    })
    await wrapper.vm.$nextTick()
    await wrapper.find(`.${buttonClass}`).trigger('click')
    expect(wrapper.vm.computeShowDialog).to.be.false
    expect(count).to.be.equals(1)
}

describe('Forms.vue', () => {
    let wrapper, axiosStub, axiosPostStub

    after(async () => {
        await axiosStub.reset()
        await axiosPostStub.reset()
    })

    beforeEach(async () => {
        localStorage.clear()

        wrapper = mount({
            shallow: false,
            component: Forms,
            props: {
                value: false, // control visibility of the dialog
            },
            computed: {
                allModulesMap: () => allModulesMap,
            },
        })
        axiosStub = sinon.stub(wrapper.vm.axios, 'get').resolves(
            Promise.resolve({
                data: {},
            })
        )
        axiosPostStub = sinon.stub(wrapper.vm.axios, 'post').resolves(Promise.resolve({}))
    })

    afterEach(async function() {
        await axiosStub.restore()
        await axiosPostStub.restore()
        await mockupCloseDialog(wrapper)
    })

    it(`Should show forms dialog when v-model value changes`, async () => {
        // go to page where '+ Create New' button is visible
        await mockupRouteChanges(wrapper, '/dashboard/services')
        await mockupOpenDialog(wrapper)
        expect(wrapper.vm.computeShowDialog).to.be.true
    })

    it(`Should auto select form Service if current route name
      doesn't match resource selection items which are 'Service, Server,
      Monitor, Filter, Listener'`, async () => {
        // mockup navigating to sessions tab on dashboard page
        await testingTextTransform(wrapper, '/dashboard/sessions', 'Service')
    })

    it(`Should auto select Service form when current page = /dashboard/services`, async () => {
        await testingTextTransform(wrapper, '/dashboard/services', 'Service')
    })
    it(`Should auto select Server form when current page = /dashboard/servers`, async () => {
        await testingTextTransform(wrapper, '/dashboard/servers', 'Server')
    })
    it(`Should auto select Server form when current page is a server details page`, async () => {
        await testingTextTransform(wrapper, '/dashboard/servers/test-server', 'Server')
    })
    it(`Should auto select Monitor form when current page is a monitor details page`, async () => {
        await testingTextTransform(wrapper, '/dashboard/monitors/test-monitor', 'Monitor')
    })
    it(`Should auto select Service form when current page is a service details page`, async () => {
        await testingTextTransform(wrapper, '/dashboard/services/test-service', 'Service')
    })

    it(`Should assign accurate Router module type object to resourceModules state`, async () => {
        await mockupResourceSelect(wrapper, 'Service')
        expect(wrapper.vm.$data.resourceModules).to.be.deep.equals(allModulesMap['Router'])
    })
    it(`Should assign accurate servers module type object to resourceModules state`, async () => {
        await mockupResourceSelect(wrapper, 'Server')
        expect(wrapper.vm.$data.resourceModules).to.be.deep.equals(allModulesMap['servers'])
    })
    it(`Should assign accurate Monitor module object to resourceModules state`, async () => {
        await mockupResourceSelect(wrapper, 'Monitor')
        expect(wrapper.vm.$data.resourceModules).to.be.deep.equals(allModulesMap['Monitor'])
    })
    it(`Should assign accurate Filter module object to resourceModules state`, async () => {
        await mockupResourceSelect(wrapper, 'Filter')
        expect(wrapper.vm.$data.resourceModules).to.be.deep.equals(allModulesMap['Filter'])
    })

    it(`Should transform authenticator parameter from string type to enum type when
      creating a listener`, async () => {
        await mockupResourceSelect(wrapper, 'Listener')
        let authenticators = allModulesMap['Authenticator']
        let authenticatorId = authenticators.map(item => `${item.id}`)
        wrapper.vm.$data.resourceModules.forEach(protocol => {
            let authenticatorParamObj = protocol.attributes.parameters.find(
                o => o.name === 'authenticator'
            )
            if (authenticatorParamObj) {
                expect(authenticatorParamObj.type).to.be.equals('enum')
                expect(authenticatorParamObj.enum_values).to.be.deep.equals(authenticatorId)
                expect(authenticatorParamObj.type).to.be.equals('')
            }
        })
    })

    it(`Should add hyphen when resourceId contains whitespace`, async () => {
        await mockupResourceSelect(wrapper, 'Monitor')
        await wrapper.setData({
            resourceId: 'test monitor',
        })
        expect(wrapper.vm.$data.resourceId).to.be.equals('test-monitor')
    })

    it(`Should validate resourceId when there is duplicated resource name`, async () => {
        await mockupResourceSelect(wrapper, 'Monitor')
        // mockup validateInfo
        await wrapper.setData({
            validateInfo: { ...wrapper.vm.$data.validateInfo, idArr: ['test-monitor'] },
        })
        await wrapper.setData({
            resourceId: 'test-monitor',
        })
        await wrapper.vm.$nextTick(() => {
            let vTextField = wrapper.find('.resource-id')
            let errorMessageDiv = vTextField.find('.v-messages__message').html()
            expect(errorMessageDiv).to.be.include('test-monitor already exists')
        })
    })

    it(`Should validate resourceId when it is empty`, async () => {
        await mockupResourceSelect(wrapper, 'Monitor')

        await wrapper.setData({
            resourceId: 'test-monitor',
        })
        await wrapper.vm.$nextTick()
        await wrapper.setData({
            resourceId: '',
        })

        await wrapper.vm.$nextTick(() => {
            let vTextField = wrapper.find('.resource-id')
            let errorMessageDiv = vTextField.find('.v-messages__message').html()
            expect(errorMessageDiv).to.be.include('id is required')
        })
    })

    it(`Should call closeModal function props to close form dialog
      when "save" button is clicked`, async () => {
        testCloseModal(wrapper, 'save')
    })

    it(`Should call closeModal function props to close form dialog
      when "close" button is clicked`, async () => {
        testCloseModal(wrapper, 'close')
    })

    it(`Should call closeModal function props to close form dialog
      when "cancel" button is clicked`, async () => {
        testCloseModal(wrapper, 'cancel')
    })
})
