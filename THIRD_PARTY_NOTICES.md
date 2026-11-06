# Third-party notices

The original batch workflow is from
[matiffeder/3DS-stuff](https://github.com/matiffeder/3DS-stuff), by matif.
Its MIT notice is preserved in [LICENSE](LICENSE).

## MIT components

These notices apply to the respective components, not to all downloaded assets:

- **[makerom](https://github.com/3DSGuy/Project_CTR/tree/master/makerom)**:
  Copyright (c) 2014 3DSGuy; Copyright (c) 2014 applestash;
  Copyright (c) 2015–2022 Jakcron.
  Setup applies the patches in `patches/` and extracts its retail key tables.
- **[PyCTR](https://github.com/ihaveamac/pyctr)**:
  Copyright (c) 2017–2023 Ian Burgwin.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Separately downloaded dependencies and data

- **[PyCryptodome](https://github.com/Legrandin/pycryptodome/blob/master/LICENSE.rst)**
  (`pycryptodomex`) uses BSD and public-domain terms detailed in its license.
- The pinned makerom build links **libblz** (GPL-3.0-or-later), **Mbed TLS**
  (Apache-2.0), and **LibYAML** (MIT). Their source and notices remain under
  `.tools-src/Project_CTR/makerom/deps/` after setup.
- The **[seed database](https://github.com/ihaveamac/3DS-rom-tools/tree/master/seeddb)**
  is retrieved separately during setup. No explicit license for that database
  was found in its upstream repository; this project's MIT license does not
  grant rights to it.

This repository is prepared for source-only publication. If distributing compiled
dependencies, retain their notices and satisfy their license obligations,
including applicable GPL corresponding-source requirements for the linked
libblz code. A source-code license does not establish permission to distribute
third-party keys, games, or other data.
