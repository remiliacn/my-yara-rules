rule DisablesWindowsDefender : suspicious {
    meta:
        name        = "DisablesWindowsDefender"
        category    = "library"
        description = "Command line ran for disabling windows defenders."
        author      = "remiliacn"
        created     = "2025-01-05"
        reliability = 80

    strings:
        $ = "Set-MpPreference -DisableRealtimeMonitoring"

    condition:
        all of them
}
