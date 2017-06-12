/*
 * Copyright 2017-present Open Networking Laboratory
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.unl.cse.netgroup;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleEvent;
import org.onosproject.net.flow.FlowRuleListener;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.meter.MeterService;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.onosproject.net.flow.FlowRuleEvent.Type.RULE_REMOVED;
import static org.onosproject.net.flow.criteria.Criterion.Type.ETH_SRC;

/**
 * Flows App ONOS application component.
 */
@Component(immediate = true)
public class FlowsApp {

    private final Logger log = LoggerFactory.getLogger(FlowsApp.class);

    // Variables for Timeouts and Flow Rule priorities
    private static final int PRIORITY = 99;
    private static final int DROP_PRIORITY =100;
    private static final int TIMEOUT_SEC = 60;

    // String Messages
    private static final String FLOW_RULE_REMOVED = "Flow rules removed from from {} to {} on {}";


    // App ID variables
    private ApplicationId applicationId;
    private static final String FLOWSAPP = "org.unl.cse.netgroup.flowsApp";

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected MeterService meterService;

    private final PacketProcessor packetProcessor = new IPPacketProcessor();
    private final FlowRuleListener flowRuleListener = new InternalFlowListener();


    private class IPPacketProcessor implements PacketProcessor{
        @Override
        public void process(PacketContext packetContext) {
            Ethernet ethernet = packetContext.inPacket().parsed();
            if(IsIPPacket(ethernet)) {
                processIPPacket(packetContext,ethernet);
            }
        }
    }

    private class InternalFlowListener implements FlowRuleListener {
        @Override
        public void event(FlowRuleEvent event) {
            FlowRule rule = event.subject();
            if (event.type() == RULE_REMOVED && rule.appId() == applicationId.id()) {
                Criterion criterion = rule.selector().getCriterion(ETH_SRC);
                MacAddress src = ((EthCriterion) criterion).mac();
                MacAddress dst = ((EthCriterion) criterion).mac();
                log.warn(FLOW_RULE_REMOVED, src, dst, rule.deviceId());
            }
        }
    }

    private void processIPPacket(PacketContext packetContext, Ethernet ethernet) {
    }

    private boolean IsIPPacket(Ethernet ethernet) {
        if (ethernet.getEtherType() == Ethernet.TYPE_IPV4) {
            if (((IPv4) ethernet.getPayload()).getProtocol() == IPv4.PROTOCOL_ICMP) {
                return true;
            }
        }
        return false;
    }

    // Define traffic selector for IP packet to be intercepted
    private final TrafficSelector intercept = DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4).matchIPProtocol(IPv4.PROTOCOL_ICMP)
            .build();


    // Application Handling
    @Activate
    protected void activate() {
        applicationId = coreService.registerApplication(FLOWSAPP);
        packetService.addProcessor(packetProcessor, PRIORITY);
        flowRuleService.addListener(flowRuleListener);
        log.info("FLOWS-APP Started");
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(packetProcessor);
        flowRuleService.removeFlowRulesById(applicationId);
        flowRuleService.removeListener(flowRuleListener);
        log.info("FLOWS-APP Stopped");
    }

}
