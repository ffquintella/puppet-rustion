# Idempotent SELinux file-context entry plus `restorecon` refresh.
#
# Records an `semanage fcontext -a` rule for `${path}(/.*)?` and triggers
# `restorecon -R` on `path` whenever the rule is added. The `unless` guard
# greps current `semanage fcontext -l` output so re-runs are no-ops.
#
# @param path
#   Absolute directory path to label.
# @param seltype
#   SELinux type to set (e.g. `etc_t`, `var_lib_t`).
# @param exec_path
#   PATH array for the underlying `exec` resources.
# @param guard
#   Command run as `onlyif` to gate the work on SELinux being enabled at
#   runtime (typically `selinuxenabled`).
#
define rustion::selinux::fcontext (
  Stdlib::Absolutepath $path,
  String               $seltype,
  Array[String]        $exec_path,
  String               $guard,
) {

  exec { "rustion-selinux-fcontext-${title}":
    command => "semanage fcontext -a -t ${seltype} '${path}(/.*)?'",
    unless  => "semanage fcontext -l | grep -E '^${path}\\(/\\.\\*\\)\\?[[:space:]].*:${seltype}:' >/dev/null",
    onlyif  => $guard,
    path    => $exec_path,
    notify  => Exec["rustion-selinux-restorecon-${title}"],
  }

  exec { "rustion-selinux-restorecon-${title}":
    command     => "restorecon -R ${path}",
    onlyif      => $guard,
    path        => $exec_path,
    refreshonly => true,
  }
}
