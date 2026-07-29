package executor

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

type networkMutationFault struct {
	status  int
	message string
	apply   bool
}

type fixtureNetwork struct {
	id         string
	name       string
	subnet     string
	labels     map[string]string
	containers map[string]any
}

type networkAPIFixture struct {
	t                    *testing.T
	spec                 NetworkSpec
	subnets              []string
	networks             map[string]*fixtureNetwork
	nextID               int
	reservationCreates   int
	finalCreates         int
	deleteTargets        []string
	reservationFaults    []networkMutationFault
	reservationDelFaults []networkMutationFault
	finalFaults          []networkMutationFault
}

func newNetworkAPIFixture(t *testing.T) (*networkAPIFixture, *DockerHTTP) {
	t.Helper()
	fixture := &networkAPIFixture{
		t: t, spec: NetworkSpecFor("tenant-a", "agent-a", 7),
		subnets: []string{"172.30.8.0/29"}, networks: make(map[string]*fixtureNetwork),
	}
	return fixture, dockerTestClient(t, fixture.serveHTTP)
}

func (f *networkAPIFixture) addReservation(subnet string) *fixtureNetwork {
	f.t.Helper()
	return f.addNetwork(
		networkReservationName(f.spec), subnet,
		networkLabels(f.spec, networkReservationAllocation, ""),
	)
}

func (f *networkAPIFixture) addFinal(subnet string, explicit bool) *fixtureNetwork {
	f.t.Helper()
	labels := legacyNetworkLabels(f.spec)
	if explicit {
		labels = networkLabels(f.spec, networkExplicitAllocation, subnet)
	}
	return f.addNetwork(f.spec.Name, subnet, labels)
}

func (f *networkAPIFixture) addNetwork(name, subnet string, labels map[string]string) *fixtureNetwork {
	f.nextID++
	network := &fixtureNetwork{
		id: "network-id-" + string(rune('a'+f.nextID)), name: name, subnet: subnet,
		labels: labels, containers: make(map[string]any),
	}
	f.networks[name] = network
	return network
}

func (f *networkAPIFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1.41/networks/"):
		f.inspectNetwork(w, strings.TrimPrefix(r.URL.Path, "/v1.41/networks/"))
	case r.Method == http.MethodPost && r.URL.Path == "/v1.41/networks/create":
		f.createNetwork(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1.41/networks/"):
		f.deleteNetwork(w, strings.TrimPrefix(r.URL.Path, "/v1.41/networks/"))
	default:
		f.t.Fatalf("unexpected Docker request %s %s", r.Method, r.URL.Path)
	}
}

func (f *networkAPIFixture) inspectNetwork(w http.ResponseWriter, ref string) {
	network := f.findNetwork(ref)
	if network == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"Id": network.id, "Name": network.name, "Driver": "bridge", "Scope": "local",
		"Internal": true, "Attachable": false, "EnableIPv6": false,
		"Options":    map[string]string{isolatedGatewayOption: isolatedGatewayMode},
		"Labels":     network.labels,
		"Containers": network.containers,
		"IPAM": map[string]any{
			"Driver": defaultIPAMDriver,
			"Config": []map[string]string{{"Subnet": network.subnet}},
		},
	})
}

func (f *networkAPIFixture) createNetwork(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		f.t.Fatal(err)
	}
	labels := decodedStringMap(f.t, body["Labels"])
	allocation := labels[networkAllocationLabel]
	name, _ := body["Name"].(string)
	subnet := ""
	var fault networkMutationFault
	switch allocation {
	case networkReservationAllocation:
		f.reservationCreates++
		if len(f.subnets) == 0 {
			f.t.Fatal("fixture has no Docker-selected subnet")
		}
		subnet, f.subnets = f.subnets[0], f.subnets[1:]
		fault, f.reservationFaults = popNetworkFault(f.reservationFaults)
	case networkExplicitAllocation:
		f.finalCreates++
		ipam, ok := body["IPAM"].(map[string]any)
		if !ok {
			f.t.Fatalf("final network IPAM=%#v", body["IPAM"])
		}
		config, ok := ipam["Config"].([]any)
		if !ok || len(config) != 1 {
			f.t.Fatalf("final network IPAM config=%#v", ipam["Config"])
		}
		allocation, ok := config[0].(map[string]any)
		if !ok {
			f.t.Fatalf("final network allocation=%#v", config[0])
		}
		subnet, _ = allocation["Subnet"].(string)
		fault, f.finalFaults = popNetworkFault(f.finalFaults)
	default:
		f.t.Fatalf("unexpected network allocation marker %q", allocation)
	}
	if fault.status == 0 || fault.apply {
		f.addNetwork(name, subnet, labels)
	}
	if fault.status != 0 {
		w.WriteHeader(fault.status)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": fault.message})
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (f *networkAPIFixture) deleteNetwork(w http.ResponseWriter, ref string) {
	f.deleteTargets = append(f.deleteTargets, ref)
	network := f.findNetwork(ref)
	if network == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	var fault networkMutationFault
	if network.labels[networkAllocationLabel] == networkReservationAllocation {
		fault, f.reservationDelFaults = popNetworkFault(f.reservationDelFaults)
	}
	if fault.status == 0 || fault.apply {
		delete(f.networks, network.name)
	}
	if fault.status != 0 {
		w.WriteHeader(fault.status)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": fault.message})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (f *networkAPIFixture) findNetwork(ref string) *fixtureNetwork {
	if network := f.networks[ref]; network != nil {
		return network
	}
	for _, network := range f.networks {
		if network.id == ref {
			return network
		}
	}
	return nil
}

func popNetworkFault(faults []networkMutationFault) (networkMutationFault, []networkMutationFault) {
	if len(faults) == 0 {
		return networkMutationFault{}, faults
	}
	return faults[0], faults[1:]
}

func decodedStringMap(t *testing.T, value any) map[string]string {
	t.Helper()
	raw, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("string map=%#v", value)
	}
	decoded := make(map[string]string, len(raw))
	for key, value := range raw {
		text, ok := value.(string)
		if !ok {
			t.Fatalf("string map value %q=%#v", key, value)
		}
		decoded[key] = text
	}
	return decoded
}

func TestCreateNetworkConvergesFromOwnedCrashState(t *testing.T) {
	t.Run("reservation only", func(t *testing.T) {
		fixture, docker := newNetworkAPIFixture(t)
		reservation := fixture.addReservation("172.30.8.0/29")
		if err := docker.CreateNetwork(context.Background(), fixture.spec); err != nil {
			t.Fatal(err)
		}
		if fixture.networks[networkReservationName(fixture.spec)] != nil ||
			fixture.networks[fixture.spec.Name] == nil ||
			!contains(fixture.deleteTargets, reservation.id) {
			t.Fatalf("networks=%#v deletes=%#v", fixture.networks, fixture.deleteTargets)
		}
	})

	t.Run("final plus stale reservation", func(t *testing.T) {
		fixture, docker := newNetworkAPIFixture(t)
		final := fixture.addFinal("172.30.8.0/29", true)
		reservation := fixture.addReservation("172.30.16.0/29")
		if err := docker.CreateNetwork(context.Background(), fixture.spec); err != nil {
			t.Fatal(err)
		}
		if fixture.networks[fixture.spec.Name] != final ||
			fixture.networks[networkReservationName(fixture.spec)] != nil ||
			fixture.finalCreates != 0 || !contains(fixture.deleteTargets, reservation.id) {
			t.Fatalf("networks=%#v creates=%d deletes=%#v", fixture.networks, fixture.finalCreates, fixture.deleteTargets)
		}
	})
}

func TestCreateNetworkNeverDeletesUnprovenReservation(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*fixtureNetwork)
	}{
		{"attached", func(network *fixtureNetwork) {
			network.containers["foreign"] = map[string]string{"Name": "foreign"}
		}},
		{"wrong role", func(network *fixtureNetwork) {
			network.labels[networkAllocationLabel] = "foreign"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture, docker := newNetworkAPIFixture(t)
			reservation := fixture.addReservation("172.30.8.0/29")
			test.mutate(reservation)
			if err := docker.CreateNetwork(context.Background(), fixture.spec); err == nil {
				t.Fatal("unproven reservation was accepted")
			}
			if fixture.networks[reservation.name] != reservation || len(fixture.deleteTargets) != 0 || fixture.finalCreates != 0 {
				t.Fatalf("networks=%#v deletes=%#v creates=%d", fixture.networks, fixture.deleteTargets, fixture.finalCreates)
			}
		})
	}
}

func TestCreateNetworkResolvesAppliedMutationResponseLoss(t *testing.T) {
	fixture, docker := newNetworkAPIFixture(t)
	lost := networkMutationFault{status: http.StatusInternalServerError, message: "response lost", apply: true}
	fixture.reservationFaults = []networkMutationFault{lost}
	fixture.reservationDelFaults = []networkMutationFault{lost}
	fixture.finalFaults = []networkMutationFault{lost}
	if err := docker.CreateNetwork(context.Background(), fixture.spec); err != nil {
		t.Fatal(err)
	}
	if fixture.networks[networkReservationName(fixture.spec)] != nil || fixture.networks[fixture.spec.Name] == nil {
		t.Fatalf("networks=%#v", fixture.networks)
	}
}

func TestCreateNetworkRetriesOnlyExactPoolOverlap(t *testing.T) {
	t.Run("overlap then success", func(t *testing.T) {
		fixture, docker := newNetworkAPIFixture(t)
		fixture.subnets = []string{"172.30.8.0/29", "172.30.16.0/29"}
		fixture.finalFaults = []networkMutationFault{{
			status: http.StatusForbidden, message: dockerPoolOverlapMessage,
		}}
		if err := docker.CreateNetwork(context.Background(), fixture.spec); err != nil {
			t.Fatal(err)
		}
		if fixture.finalCreates != 2 || fixture.reservationCreates != 2 ||
			fixture.networks[fixture.spec.Name].subnet != "172.30.16.0/29" {
			t.Fatalf("reservation creates=%d final creates=%d final=%#v",
				fixture.reservationCreates, fixture.finalCreates, fixture.networks[fixture.spec.Name])
		}
	})

	t.Run("generic failure", func(t *testing.T) {
		fixture, docker := newNetworkAPIFixture(t)
		fixture.finalFaults = []networkMutationFault{{status: http.StatusInternalServerError, message: "daemon unavailable"}}
		if err := docker.CreateNetwork(context.Background(), fixture.spec); err == nil {
			t.Fatal("generic Docker failure was retried into success")
		}
		if fixture.finalCreates != 1 || fixture.reservationCreates != 1 {
			t.Fatalf("reservation creates=%d final creates=%d", fixture.reservationCreates, fixture.finalCreates)
		}
	})

	t.Run("bounded exhaustion", func(t *testing.T) {
		fixture, docker := newNetworkAPIFixture(t)
		fixture.subnets = []string{"172.30.8.0/29", "172.30.16.0/29", "172.30.24.0/29"}
		overlap := networkMutationFault{status: http.StatusForbidden, message: dockerPoolOverlapMessage}
		fixture.finalFaults = []networkMutationFault{overlap, overlap, overlap}
		if err := docker.CreateNetwork(context.Background(), fixture.spec); err == nil ||
			!strings.Contains(err.Error(), "after 3 attempts") {
			t.Fatalf("bounded overlap error=%v", err)
		}
		if fixture.finalCreates != maxNetworkAllocationAttempts ||
			fixture.networks[fixture.spec.Name] != nil ||
			fixture.networks[networkReservationName(fixture.spec)] != nil {
			t.Fatalf("networks=%#v final creates=%d", fixture.networks, fixture.finalCreates)
		}
	})
}

func TestFreshNetworkCreationRejectsUnmarkedLegacyFinal(t *testing.T) {
	fixture, docker := newNetworkAPIFixture(t)
	legacy := fixture.addFinal("172.30.8.0/29", false)
	observed, err := docker.InspectNetwork(context.Background(), fixture.spec.Name)
	if err != nil || !observed.Managed || observed.ExplicitIPAM {
		t.Fatalf("legacy network=%#v err=%v", observed, err)
	}
	if err := docker.CreateNetwork(context.Background(), fixture.spec); err == nil {
		t.Fatal("fresh creation adopted an unmarked legacy final")
	}
	if fixture.networks[fixture.spec.Name] != legacy || len(fixture.deleteTargets) != 0 {
		t.Fatalf("legacy network was mutated: networks=%#v deletes=%#v", fixture.networks, fixture.deleteTargets)
	}
}

func TestRemoveNetworkPreflightsFinalAndReservationBeforeDeletingEither(t *testing.T) {
	fixture, docker := newNetworkAPIFixture(t)
	final := fixture.addFinal("172.30.8.0/29", true)
	reservation := fixture.addReservation("172.30.16.0/29")
	reservation.containers["foreign"] = map[string]string{"Name": "foreign"}
	if err := docker.RemoveNetwork(context.Background(), fixture.spec.Name); err == nil {
		t.Fatal("cleanup accepted an attached reservation")
	}
	if fixture.networks[fixture.spec.Name] != final ||
		fixture.networks[networkReservationName(fixture.spec)] != reservation ||
		len(fixture.deleteTargets) != 0 {
		t.Fatalf("cleanup mutated an unproven topology: networks=%#v deletes=%#v", fixture.networks, fixture.deleteTargets)
	}
}
