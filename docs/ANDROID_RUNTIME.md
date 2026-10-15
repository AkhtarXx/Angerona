# Managed Android runtime

Angerona's default dynamic-analysis target is an owned, disposable official
Android Emulator AVD using a rootable AOSP system image. It does not install an
APK on the first device returned by ADB.

## One-time host preparation

Install the official Android SDK command-line tools, then use `sdkmanager` from
that same SDK root to install a pinned toolchain and image. License acceptance
is intentionally interactive and is never automated by Angerona.

```bash
sdkmanager --licenses
sdkmanager "platform-tools" "emulator" "system-images;android-35;default;x86_64"
export ANGERONA_ANDROID_SDK_ROOT=/absolute/path/to/android-sdk
```

Linux runners should expose KVM to the audit user. The default profile also
requires enough free space for a 4 GiB guest data partition, emulator state,
the APK, and recovered evidence.

Frida client and server versions must match exactly. Either place a verified
server on disk and set `ANGERONA_FRIDA_SERVER_PATH`, or opt into downloading the
matching official release asset with `--runtime-auto-provision`.

## Audit commands

```bash
angerona android-doctor --runtime --runtime-provider avd --runtime-api 35

angerona android-audit app.apk \
  --runtime \
  --runtime-provider avd \
  --runtime-api 35 \
  --authorization-ref ENGAGEMENT-ID \
  --output report.json
```

With `--runtime-provider auto` (the default), a supplied `--device-serial` means
connected-lab-device mode; without a serial Angerona creates its own AVD.
Physical devices are never selected implicitly.

The managed lifecycle creates a unique AVD and private ADB server, performs a
cold clean boot, verifies root, provisions and smoke-tests an exact-version
Frida server, installs and hash-verifies the supplied base APK, collects runtime
surface and DEX evidence before uninstall, and then destroys the AVD. Any boot,
identity, instrumentation, evidence, or teardown failure keeps the audit
partial.

## Evidence boundaries

- A native x86_64 AVD run cannot close ARM64 native-code coverage.
- An APK with materially different libraries for multiple ABIs remains dynamic
  incomplete until each required native lane is exercised.
- Native translation is exploratory and requires
  `--allow-native-translation`; it is recorded as a limitation.
- Google Play images are not the root/Frida lane. Apps requiring Play services
  need a separately labelled non-root or modified-Gadget lane.
- Emulator detection, Play Integrity, TEE/StrongBox, hardware-backed keystore,
  OEM/HAL, baseband, NFC/Bluetooth, and real-sensor behavior require an
  authorized physical-device escalation.
- A 200–300 MiB APK is supported by the streaming/hash and scaled-timeout path,
  but doctor/storage gates must pass; large recovered payloads can require a
  larger `data_partition_mb` policy than the 4 GiB default.

Cuttlefish is the planned secondary fleet backend. It is not silently used as
a fallback when the official Emulator cannot start.
