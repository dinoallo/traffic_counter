# traffic Specification (Delta)

## ADDED Requirements

### Requirement: Attach programs in pod network namespaces
The system SHALL discover pod network namespaces on the host and attempt to attach the traffic counting eBPF programs to the `eth0` interface within each namespace when it exists.

#### Scenario: Attach in a namespace with `eth0`
- **GIVEN** a pod network namespace containing an `eth0` interface
- **WHEN** the pod provider runs its attachment routine
- **THEN** the ingress and egress programs SHALL be attached to `eth0` within that namespace

#### Scenario: Namespace without `eth0`
- **GIVEN** a pod network namespace that does not contain an `eth0` interface
- **WHEN** the pod provider runs its attachment routine
- **THEN** the system SHALL skip attachment for that namespace without failing the overall routine

#### Scenario: Transient namespace disappears
- **GIVEN** a pod network namespace that is deleted during discovery or attachment
- **WHEN** the pod provider attempts to enter or attach within that namespace
- **THEN** the system SHALL handle the error gracefully and continue processing remaining namespaces