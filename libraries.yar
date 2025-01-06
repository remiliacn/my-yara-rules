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

rule PythonSmtpUsage : odd {
    meta:
        name        = "PythonSmtpUsage"
        category    = "library"
        description = "Python program that used SMTP imports."
        author      = "remiliacn"
        created     = "2025-01-05"
        reliability = 70

    strings:
        $ = "smtplib" ascii wide
		$ = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{,3}/ ascii wide

    condition:
        all of them
}
