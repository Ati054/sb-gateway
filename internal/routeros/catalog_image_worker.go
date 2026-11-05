package routeros

func catalogImageArrivalSource(schema int) string {
	if schema != 1 {
		return ""
	}
	return `    :local arrivals [/system/script/find where name="SB-GATEWAY-catalog-image-arrival"]
    :if ([:len $arrivals] > 1) do={ :error "SB-GATEWAY catalog arrival receipt is ambiguous" }
    :if ([:len $arrivals] = 1) do={ :if ([/system/script/get $arrivals comment] != "SB-GATEWAY catalog image arrival") do={ :error "SB-GATEWAY catalog arrival receipt is not owned" } }
    :if ([:len $arrivals] = 0) do={ /system/script/add name="SB-GATEWAY-catalog-image-arrival" policy=read comment="SB-GATEWAY catalog image arrival" source=""; :set arrivals [/system/script/find where name="SB-GATEWAY-catalog-image-arrival"] }
    :local arrival [:deserialize from=json value=[:serialize to=json value=$receipt]]
    :set ($arrival->"phase") "completed"
    /system/script/set $arrivals source=[:serialize to=json value=$arrival]
    :local arrivalReadback [:deserialize from=json value=[/system/script/get $arrivals source]]
    :if ([:serialize to=json value=$arrivalReadback] != [:serialize to=json value=$arrival]) do={ :error "SB-GATEWAY catalog arrival receipt readback failed" }`
}

// The marker is installed only after a durable stopped-predecessor handoff.
// Every rollback branch selects mounts by its target root. Neither a target
// version string nor the failed image's shared mounts proves compatibility.
func catalogImageWorkerCompatibilitySource() string {
	return `:local catalogContract
:local catalogMarkers [/system/script/find where name="SB-GATEWAY-catalog-data-contract"]
:if ([:len $catalogMarkers] > 1) do={ :error "SB-GATEWAY catalog data contract is ambiguous" }
:if ([:len $catalogMarkers] = 1) do={
  :if ([/system/script/get $catalogMarkers comment] != "SB-GATEWAY catalog data compatibility") do={ :error "SB-GATEWAY catalog data contract is not owned" }
  :set catalogContract [:deserialize from=json value=[/system/script/get $catalogMarkers source]]
  :if ((($catalogContract->"format_version") != 1) || (($catalogContract->"state") != "prepared") || (($catalogContract->"catalog_schema") != 1)) do={ :error "SB-GATEWAY catalog data contract is invalid" }
}
:local catalogTargetMountlists do={
  :local targetRoot [:tostr $1]
  :if ([:pick $targetRoot 0 1] = "/") do={ :set targetRoot [:pick $targetRoot 1 [:len $targetRoot]] }
  :local fallback $2
  :local contract $3
  :if ([:typeof $contract] != "array") do={ :return $fallback }
  :if ($targetRoot = ($contract->"producer_root")) do={ :return $fallback }
  :if ($targetRoot != ($contract->"previous_root")) do={ :error "SB-GATEWAY rollback image has no matching data handoff" }
  :if (($contract->"previous_catalog_schema") = 1) do={ :return $fallback }
  :local handoff [:tostr ($contract->"handoff")]
  :local sbCatalogMountlist [:tostr ($contract->"mountlist")]
  :if (([:len $handoff] != 64) || ($sbCatalogMountlist != ("sb-catalog-compat-" . [:pick $handoff 0 16]))) do={ :error "SB-GATEWAY rollback compatibility identity is invalid" }
  :local mounts [/container/mounts/find where list=$sbCatalogMountlist]
  :if ([:len $mounts] != 4) do={ :error "SB-GATEWAY rollback compatibility mounts are incomplete" }
  :local seen [:toarray ""]
  :foreach mount in=$mounts do={
    :local destination [/container/mounts/get $mount dst]
    :local source [:tostr [/container/mounts/get $mount src]]
    :if (([/container/mounts/get $mount disabled] = true) || ([/container/mounts/get $mount comment] != ("SB-GATEWAY catalog data compatibility " . $handoff))) do={ :error "SB-GATEWAY rollback compatibility mount is not owned" }
    :if (($destination != "/config") && ($destination != "/state") && ($destination != "/data") && ($destination != "/logs")) do={ :error "SB-GATEWAY rollback compatibility destination is invalid" }
    :if (($seen->$destination) = true) do={ :error "SB-GATEWAY rollback compatibility destination is duplicated" }
    :set ($seen->$destination) true
	:if ([:pick $source 0 1] = "/") do={ :set source [:pick $source 1 [:len $source]] }
	:local sourceIndex 0
	:if ($destination = "/data") do={ :set sourceIndex 1 }
	:if ($destination = "/logs") do={ :set sourceIndex 2 }
	:if ($destination = "/state") do={ :set sourceIndex 3 }
	:local expectedSources ($contract->"mount_sources")
	:if ($source != ($expectedSources->$sourceIndex)) do={ :error "SB-GATEWAY rollback compatibility mount source changed" }
    :if ($destination != "/logs") do={ :if ([:typeof [:find $source ("/.catalog-compat/" . $handoff . $destination)]] != "num") do={ :error "SB-GATEWAY rollback compatibility source is invalid" } }
  }
  :return [:toarray $sbCatalogMountlist]
}`
}
