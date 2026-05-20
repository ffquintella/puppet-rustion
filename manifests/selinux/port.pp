# Idempotent SELinux port-type label via `semanage port`.
#
# Adds an `semanage port -a` rule when the given (port, protocol) tuple is
# not already labeled with `seltype`. The `unless` guard checks current
# `semanage port -l` output so re-runs are no-ops.
#
# @param port
#   TCP/UDP port number to label (string-encoded; just digits).
# @param protocol
#   `tcp` or `udp`.
# @param seltype
#   SELinux port type to set (e.g. `ssh_port_t`, `http_port_t`).
# @param exec_path
#   PATH array for the underlying `exec` resources.
# @param guard
#   Command run as `onlyif` to gate the work on SELinux being enabled at
#   runtime (typically `selinuxenabled`).
#
define rustion::selinux::port (
  Pattern[/\A\d+\z/]    $port,
  Enum['tcp', 'udp']    $protocol,
  String                $seltype,
  Array[String]         $exec_path,
  String                $guard,
) {

  exec { "rustion-selinux-port-${title}":
    command => "semanage port -a -t ${seltype} -p ${protocol} ${port}",
    unless  => "semanage port -l | grep -E '^${seltype}[[:space:]]+${protocol}[[:space:]]+.*\\b${port}\\b' >/dev/null",
    onlyif  => $guard,
    path    => $exec_path,
  }
}
