NOTICE
======

NetSpecter includes code derived from the following third-party project:

  Airgorah
  Copyright (c) 2026 Martin Olivier
  https://github.com/martin-olivier/airgorah
  Licensed under the MIT License.

    MIT License
    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

Modifications and additions made by AbD02018 in NetSpecter (1.0.0):
  - PMKID auto-attack
  - WPS attack module (Pixie Dust, Reaver, Online Brute, NULL PIN)
  - WEP IVs collection + cracking
  - WPA3-SAE detection and transition-mode identification
  - Hidden SSID discovery (probe-request analysis + targeted deauth-to-reveal)
  - Fluxion-style Evil Twin (hostapd + dnsmasq + captive portal + credential
    capture)
  - SmartWizard guided UI flow
  - HTML / PDF pentest report generator
  - Audit log + explicit consent gate at startup

The full text of the MIT License from the upstream project is available in the
upstream repository at:
  https://github.com/martin-olivier/airgorah/blob/master/LICENSE

The GPL-3.0 license under which NetSpecter is distributed is compatible with
distribution alongside MIT-licensed portions.