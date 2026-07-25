function list(value) {
  return Array.isArray(value) ? value : [];
}

function uniqueSorted(values) {
  return [...new Set(values.filter(Boolean))].sort();
}

function observationKey(tenantID, instanceID) {
  return `${tenantID}\u0000${instanceID}`;
}

function newestObservation(current, candidate) {
  if (!current) {
    return candidate;
  }
  if ((candidate.instance_generation || 0) !== (current.instance_generation || 0)) {
    return (candidate.instance_generation || 0) > (current.instance_generation || 0) ? candidate : current;
  }
  return String(candidate.updated_at || "") > String(current.updated_at || "") ? candidate : current;
}

export function workspaceLifecycle(deployment) {
  if (deployment?.fork?.expires_at) {
    return "temporary";
  }
  if (deployment?.fork) {
    return "resumable";
  }
  if (list(deployment?.instances).length > 1) {
    return "fleet";
  }
  return "managed";
}

export function deriveWorkspaceProjection(deploymentsPage, agentsPage) {
  const deployments = list(deploymentsPage?.deployments);
  const agents = list(agentsPage?.agents);
  const observations = new Map();
  for (const agent of agents) {
    if (!agent?.tenant_id || !agent?.instance_id) {
      continue;
    }
    const key = observationKey(agent.tenant_id, agent.instance_id);
    observations.set(key, newestObservation(observations.get(key), agent));
  }

  const claimed = new Set();
  const workspaces = deployments.map((deployment) => {
    const members = list(deployment.instances).map((instance) => {
      const key = observationKey(deployment.tenant_id, instance.instance_id);
      const observation = observations.get(key) || null;
      claimed.add(key);
      return {
        ...instance,
        node_id: instance.node_id || observation?.node_id || "",
        observed_status: observation?.observed_status || "not observed",
        runtime_ref: observation?.runtime_ref || "",
        service_id: observation?.service_id || "",
        connector_ids: list(observation?.connector_ids),
        egress_route_ids: list(observation?.egress_route_ids),
        last_activity_at: observation?.updated_at || instance.transitioned_at || "",
        latest_terminal_status: observation?.latest_terminal_status || "",
      };
    });
    const phaseCounts = {};
    for (const member of members) {
      phaseCounts[member.phase] = (phaseCounts[member.phase] || 0) + 1;
    }
    return {
      id: deployment.deployment_id || deployment.id,
      tenant_id: deployment.tenant_id,
      agent_name: deployment.agent_name,
      generation: deployment.generation,
      revision: deployment.revision,
      phase: deployment.phase,
      desired_state: deployment.desired_state,
      lifecycle: workspaceLifecycle(deployment),
      expires_at: deployment.fork?.expires_at || "",
      fork: deployment.fork || null,
      rollout: deployment.rollout || null,
      members,
      phase_counts: phaseCounts,
      node_ids: uniqueSorted(members.map((member) => member.node_id)),
      connector_ids: uniqueSorted(members.flatMap((member) => member.connector_ids)),
      egress_route_ids: uniqueSorted(members.flatMap((member) => member.egress_route_ids)),
      service_ids: uniqueSorted(members.map((member) => member.service_id)),
    };
  });
  workspaces.sort((left, right) => {
    return String(left.tenant_id).localeCompare(String(right.tenant_id)) ||
      String(left.id).localeCompare(String(right.id));
  });

  const directInstances = agents.filter((agent) => {
    if (!agent?.tenant_id || !agent?.instance_id) {
      return true;
    }
    return !claimed.has(observationKey(agent.tenant_id, agent.instance_id));
  });

  return {workspaces, directInstances};
}

export function workspaceMatches(workspace, query, lifecycle) {
  if (lifecycle && lifecycle !== "all" && workspace.lifecycle !== lifecycle) {
    return false;
  }
  const needle = String(query || "").trim().toLocaleLowerCase();
  if (!needle) {
    return true;
  }
  return [
    workspace.id,
    workspace.tenant_id,
    workspace.agent_name,
    workspace.phase,
    ...workspace.node_ids,
    ...workspace.connector_ids,
    ...workspace.egress_route_ids,
    ...workspace.service_ids,
    ...workspace.members.map((member) => member.instance_id),
  ].some((value) => String(value || "").toLocaleLowerCase().includes(needle));
}
