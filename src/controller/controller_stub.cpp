// The controller implementation is Windows-only for now; the Linux port is planned in
// docs/LINUX_PORT_PLAN.md (M3 adds the Linux controller). run/attach/doctor are rejected
// at the application layer with exit code 5 on this platform. This translation unit keeps
// the noleax-controller target valid until the Linux controller lands.
namespace noleax::controller {

// Intentionally empty.

}  // namespace noleax::controller
