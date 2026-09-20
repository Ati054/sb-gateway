# SB-GATEWAY single-entry local installer.
# Upload this release bundle and one private variables.rsc into the same
# sb-gateway directory, then import only this file. Every required artifact is
# checked before the first mutating step.

:local variablesSuffix "/variables.rsc"
:local variablesPath ""
:foreach candidate in=[/file/find where name~"variables.rsc"] do={
  :local candidatePath [/file/get $candidate name]
  :if ([:len $candidatePath] >= [:len $variablesSuffix]) do={
    :local suffixStart ([:len $candidatePath] - [:len $variablesSuffix])
    :if ([:pick $candidatePath $suffixStart [:len $candidatePath]] = $variablesSuffix) do={
      :if ([:len $variablesPath] > 0) do={ :error "SB-GATEWAY: multiple sb-gateway/variables.rsc files found; keep exactly one release bundle" }
      :set variablesPath $candidatePath
    }
  }
}
:if ([:len $variablesPath] = 0) do={ :error "SB-GATEWAY: place a private variables.rsc in the uploaded sb-gateway directory" }

:local bundleRoot [:pick $variablesPath 0 ([:len $variablesPath] - [:len $variablesSuffix])]
:foreach requiredFile in={"preflight.rsc";"webfig-bootstrap.rsc";"fasttrack-patch.rsc";"install.rsc";"watchdog.rsc"} do={
  :local requiredPath ($bundleRoot . "/" . $requiredFile)
  :if ([:len [/file/find where name=$requiredPath]] != 1) do={ :error ("SB-GATEWAY: release bundle is incomplete: " . $requiredPath) }
}

:log info ("SB-GATEWAY: bootstrap loading private variables from " . $variablesPath)
/import file-name=$variablesPath
:global "SB_STORAGE_ROOT"
:if ($"SB_STORAGE_ROOT" != $bundleRoot) do={ :error "SB-GATEWAY: variables.rsc SB_STORAGE_ROOT must match its release-bundle directory" }

:log info "SB-GATEWAY: bootstrap 1/5 preflight"
/import file-name=($bundleRoot . "/preflight.rsc")
:log info "SB-GATEWAY: bootstrap 2/5 dedicated RouterOS REST account"
/import file-name=($bundleRoot . "/webfig-bootstrap.rsc")
:log info "SB-GATEWAY: bootstrap 3/5 FastTrack compatibility"
/import file-name=($bundleRoot . "/fasttrack-patch.rsc")
:log info "SB-GATEWAY: bootstrap 4/5 container and owned network objects"
/import file-name=($bundleRoot . "/install.rsc")
:log info "SB-GATEWAY: bootstrap 5/5 fail-open watchdog"
/import file-name=($bundleRoot . "/watchdog.rsc")
:if ($"SB_IMAGE_SOURCE" = "file") do={
  :local imageFile [/file/find where name=$"SB_IMAGE_FILE"]
  :if ([:len $imageFile] = 1) do={ :do { /file/remove $imageFile } on-error={ :log warning "SB-GATEWAY: extracted image archive cleanup is pending" } }
}
:foreach transientFile in={"bootstrap.rsc";"fasttrack-patch.rsc";"install.rsc";"preflight.rsc";"variables.rsc";"watchdog.rsc";"webfig-bootstrap.rsc"} do={
  :local transientPath ($bundleRoot . "/" . $transientFile)
  :local transientId [/file/find where name=$transientPath]
  :if ([:len $transientId] = 1) do={ :do { /file/remove $transientId } on-error={ :log warning ("SB-GATEWAY: one-shot installer cleanup is pending: " . $transientPath) } }
}
:log info "SB-GATEWAY: bootstrap complete; open the container panel and finish the first-launch wizard"
