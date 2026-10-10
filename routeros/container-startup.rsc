# SB-GATEWAY storage-aware boot. Import before install.rsc.
# This installer never starts or changes a container.
:local initiallyDisabled ($1 = true)
:local readyId [/system/script/find where name="SB-GATEWAY-storage-ready"]
:local bootId [/system/script/find where name="SB-GATEWAY-container-startup"]
:local scheduleId [/system/scheduler/find where name="SB-GATEWAY-container-startup"]
:if (([:len $readyId] > 1) || ([:len $bootId] > 1) || ([:len $scheduleId] > 1)) do={ :error "SB-GATEWAY startup objects are ambiguous" }
:if ([:len $readyId] = 1) do={ :if ([/system/script/get $readyId comment] != "SB-GATEWAY storage readiness") do={ :error "SB-GATEWAY storage probe is not owned" } }
:if ([:len $bootId] = 1) do={ :if ([/system/script/get $bootId comment] != "SB-GATEWAY storage-aware startup") do={ :error "SB-GATEWAY startup script is not owned" } }
:if ([:len $scheduleId] = 1) do={ :if ([/system/scheduler/get $scheduleId comment] != "SB-GATEWAY storage-aware startup scheduler") do={ :error "SB-GATEWAY startup scheduler is not owned" } }

:if ([:len $readyId] = 0) do={
  /system/script/add name="SB-GATEWAY-storage-ready" policy=read source="" comment="SB-GATEWAY storage readiness"
  :set readyId [/system/script/find where name="SB-GATEWAY-storage-ready"]
}
/system/script/set $readyId source={
  :local target $1
  :local disksOnly ($2 = true)
  :local pathReady do={
    :local path [:tostr $1]
    :if ([:pick $path 0 1] = "/") do={ :set path [:pick $path 1 [:len $path]] }
    :local separator [:find $path "/"]
    :if (([:typeof $separator] != "num") || ($separator = 0)) do={ :return false }
    :local diskName [:pick $path 0 $separator]
    :local kind ""
    :do {
      :if ([/file/get $diskName type] != "disk") do={ :return false }
      :set kind [/file/get $path type]
    } on-error={ :return false }
    :return (($kind = "directory") || ($kind = "container store"))
  }
  :local root [/container/get $target root-dir]
  :if ([$pathReady $root] != true) do={ :return false }
  :if ([:pick $root 0 1] = "/") do={ :set root [:pick $root 1 [:len $root]] }
  :local rootDisk [:pick $root 0 [:find $root "/"]]
  :local checkedDisks [:toarray ""]
  :set ($checkedDisks->$rootDisk) true
  :local lists [/container/get $target mountlists]
  :if ([:len $lists] = 0) do={ :return true }
  :if ([:typeof $lists] != "array") do={ :return false }
  :foreach mountListName in=$lists do={
    :local mounts [/container/mounts/find where list=$mountListName]
    :if ([:len $mounts] = 0) do={ :return false }
    :foreach mountId in=$mounts do={
      :if ([/container/mounts/get $mountId disabled] = false) do={
        :local source [/container/mounts/get $mountId src]
        :if ($disksOnly = true) do={
          :if ([:pick $source 0 1] = "/") do={ :set source [:pick $source 1 [:len $source]] }
          :local separator [:find $source "/"]
          :if (([:typeof $separator] != "num") || ($separator = 0)) do={ :return false }
          :local diskName [:pick $source 0 $separator]
          :if (($checkedDisks->$diskName) != true) do={
            :do { :if ([/file/get $diskName type] != "disk") do={ :return false } } on-error={ :return false }
            :set ($checkedDisks->$diskName) true
          }
        } else={ :if ([$pathReady $source] != true) do={ :return false } }
      }
    }
  }
  :return true
}
:if ([:len $bootId] = 0) do={
  /system/script/add name="SB-GATEWAY-container-startup" policy=read,write,test source="" comment="SB-GATEWAY storage-aware startup"
  :set bootId [/system/script/find where name="SB-GATEWAY-container-startup"]
}
/system/script/set $bootId source={
  :local finished ([:len [/system/script/job/find where script="SB-GATEWAY-container-startup"]] > 1)
  :local probe [/system/script/find where name="SB-GATEWAY-storage-ready" and comment="SB-GATEWAY storage readiness"]
  :if ([:len $probe] != 1) do={ :error "SB-GATEWAY storage probe is missing or ambiguous" }
  :local ready [:parse [/system/script/get $probe source]]
  :local stable 0
  :local attempt 0
  :while (($finished = false) && ($attempt < 150)) do={
    :local busy (([:len [/system/scheduler/find where name="SB-GATEWAY-image-update"]] > 0) || ([:len [/system/script/find where name="SB-GATEWAY-image-update-transfer"]] > 0))
    :if ($busy = true) do={ :set finished true }
    :local targets [/container/find where comment="SB-GATEWAY container"]
    :if ([:len $targets] > 1) do={ :error "SB-GATEWAY startup container is ambiguous" }
    :if (([:len $targets] = 1) && ($busy = false)) do={
      :local target [:pick $targets 0]
      :if (([/container/get $target running] = true) || ([/container/get $target healthy] = true)) do={ :set finished true } else={
        :if ([/container/get $target stopped] = true) do={
          :local available false
          :do { :set available [$ready $target true] } on-error={}
          :if ($available = true) do={ :set stable ($stable + 1) } else={ :set stable 0 }
          :if ($stable >= 2) do={
            :local foldersReady false
            :do { :set foldersReady [$ready $target] } on-error={}
            :if (([:len [/system/scheduler/find where name="SB-GATEWAY-image-update"]] > 0) || ([:len [/system/script/find where name="SB-GATEWAY-image-update-transfer"]] > 0) || ([/container/get $target stopped] != true) || ([/container/get $target comment] != "SB-GATEWAY container")) do={ :set finished true; :set foldersReady false }
            :if ($foldersReady = true) do={
              /container/start $target
              :log info "SB-GATEWAY: storage ready; boot container start requested"
            } else={ :if ($finished = false) do={ :log error "SB-GATEWAY: mount source folders are missing; boot start refused" } }
            :set finished true
          }
        } else={ :set stable 0 }
      }
    } else={ :set stable 0 }
    :set attempt ($attempt + 1)
    :if ($finished = false) do={ :delay 2s }
  }
  :if ($finished = false) do={ :log error "SB-GATEWAY: boot storage wait expired; container not started" }
}
:if ([:len $scheduleId] = 0) do={
  /system/scheduler/add name="SB-GATEWAY-container-startup" interval=0s start-time=startup on-event="/system/script/run SB-GATEWAY-container-startup" policy=read,write,test disabled=$initiallyDisabled comment="SB-GATEWAY storage-aware startup scheduler"
} else={
  /system/scheduler/set $scheduleId interval=0s start-time=startup on-event="/system/script/run SB-GATEWAY-container-startup" policy=read,write,test
  :if ($initiallyDisabled = true) do={ /system/scheduler/disable $scheduleId }
}
