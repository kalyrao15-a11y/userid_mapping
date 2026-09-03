# User-ID Mapping

Push static User-IP mappings to a Palo Alto Networks NGFW through the XML API. The firewall applies the mapping immediately; no commit is required.

Use either the Python or PowerShell script. Both read `.env` and send `mappings.xml` as `type=user-id`.

## Requirements

- Network reachability to the firewall management interface
- An XML API key with User-ID privileges
- One of:
  - Python 3 plus the packages in `requirements.txt`
  - PowerShell 5.1+ (Windows)

## Setup

1. Copy the env template and fill in firewall details:

   ```powershell
   Copy-Item .env.example .env
   ```

2. Generate an XML API key (replace hostname, username, and password):

   ```powershell
   curl.exe -k -X POST "https://<hostname>/api/?type=keygen&user=<username>&password=<password>"
   ```

   A successful response includes the key:

   ```xml
   <response status="success">
     <result>
       <key>LUFRPT1...</key>
     </result>
   </response>
   ```

   Copy the `<key>` value into `PAN_API_KEY`. The account used here must have User-ID API privileges.

3. Edit `.env`:

   | Variable | Required | Description |
   |---|---|---|
   | `PAN_HOSTNAME` | yes | Firewall hostname or IP (no `https://`) |
   | `PAN_API_KEY` | yes | XML API key |
   | `PAN_VSYS` | no | Virtual system. Default: `vsys1` |
   | `PAN_VERIFY_SSL` | no | Set `true` when the device cert is trusted. Default: `false` |

4. For the Python script, install dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```

Do not commit `.env`. It is listed in `.gitignore`.

## Mappings file

Edit `mappings.xml`. It must be a `uid-message` with `login` and/or `logout` entries:

```xml
<uid-message>
  <version>1.0</version>
  <type>update</type>
  <payload>
    <login>
      <entry name="domain\username" ip="192.0.2.10" timeout="60"/>
    </login>
  </payload>
</uid-message>
```

`timeout` is minutes:

- Omit it to use the firewall User-ID default (often 45 minutes).
- `timeout="0"` means no expiration (`Never`).

## Usage

Use either the Python script or the PowerShell script, not both on one line.

Preview the XML without sending it:

```powershell
python push_user_mapping.py --dry-run
.\push_user_mapping.ps1 -DryRun
```

Push the default `mappings.xml`:

```powershell
python push_user_mapping.py
.\push_user_mapping.ps1
```

Push a different file:

```powershell
python push_user_mapping.py --file path\to\mappings.xml
.\push_user_mapping.ps1 -File path\to\mappings.xml
```

Clear all User-IP mappings created by the XML API only. Does not remove mappings learned from User-ID agents, syslog, or other sources:

```powershell
python push_user_mapping.py --clear
.\push_user_mapping.ps1 -Clear
```

Clear the XML API mapping for a single IP address:

```powershell
python push_user_mapping.py --clear-ip 192.0.2.10
.\push_user_mapping.ps1 -ClearIp 192.0.2.10
```

Preview any payload before sending:

```powershell
python push_user_mapping.py --clear --dry-run
python push_user_mapping.py --clear-ip 192.0.2.10 --dry-run
.\push_user_mapping.ps1 -Clear -DryRun
.\push_user_mapping.ps1 -ClearIp 192.0.2.10 -DryRun
```

A successful push prints `Firewall accepted the User-ID mapping.`, the login/logout entries that were sent, and the API response.
