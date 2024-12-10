rule PyInstallerApp {
    meta:
        name        = "PyInstallerApp"
        category    = "installer"
        description = "Identifies Pyinstaller signature"
        author      = "remiliacn"
        created     = "2024-12-09"
        reliability = 50

    strings:
        $s = /load PyInstaller/i

    condition:
        $s
}
