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
package org.unl.cse.netgroup.rest;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.onosproject.rest.AbstractWebResource;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

/**
 * Flows App web resource.
 */
@Path("flowsapp")
public class FlowsAppWebResource extends AbstractWebResource {

    /**
     * Get hello flowsApp greeting.
     *
     * @return 200 OK
     * @onos.rsModel FlowsAppGet
     */
    @GET
    @Path("info")
    public Response getGreeting() {
        ObjectNode node = mapper().createObjectNode().put("hello", "flowsApp");
        return ok(node).build();
    }

}
