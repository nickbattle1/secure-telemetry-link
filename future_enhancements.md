# Future Enhancements

This document outlines potential improvements for real-world aerospace implementation: rewriting in embedded C, running on STM32 flight hardware, replacing TCP with RF/satellite links, and adopting avionics standards.

---

## Phase 2: Real-World Application Enhancements

These improvements reflect how this system would evolve into an actual aerospace/defence secure telemetry subsystem. They are out of scope for this current project.

### 1. Hardware Root of Trust

Hardware root-of-trust implementations (TPM, secure element, TrustZone, etc.) are essential in real production systems for:

- Secure boot verification
- Tamper-resistant key storage
- Hardware-backed attestation

**Current Status:**
- Not required for this assignment demonstration
- Difficult to demonstrate cleanly in a short academic project
- Mentioned as future work and real-world hardening consideration

In a production aerospace system, the Raspberry Pi would be replaced with certified avionics hardware featuring hardware security modules (HSMs) or secure elements to protect cryptographic keys and ensure system integrity.

### 2. Embedded Implementation

- Port protocol from Python to C for micro-controller environments.
- Target STM32 or similar flight-controller hardware.
- Use hardware-accelerated AES and SHA peripherals to maintain security protocols and optimise performance
- Store keys in secure flash or hardware security elements to prevent key theft and protect cryptographic identities

### 3. Replace TCP With Physical Communication Links

- Swap TCP sockets for RF transmitter/receiver modules, UHF/VHF, LoRa, SATCOM, or custom SDR links.
- Add framing, CRC, retransmission logic, and loss handling.
- Model real ADS-C/flight telemetry link conditions.

### 4. Real Avionics Data Sources

Replace simulated CSV telemetry with:

- INS/GNSS outputs
- FMS waypoint updates
- Integrate with actual aircraft sensor buses.

### 5. Multi-Aircraft & Multi-Ground Scaling

- Add session multiplexing/threading to support multiple aircraft.
- Rate limiting, session management, and replay windows per air craft

### 6. Periodic Re-Keying after N Messages / T Seconds

In a real system, long-lived sessions would periodically refresh keys (full or abbreviated re-handshake after N frames or T seconds) to limit the impact of any key compromise.

**Current Status:**
- This project keeps a single session key per connection for simplicity.
- The transcript-based KDF design cleanly supports later re-keying.
- Could be implemented by triggering a new handshake after a message counter threshold or time interval.

**Implementation Considerations:**
- Add message counter or session timer to track when re-keying is needed.
- Perform abbreviated handshake (reusing authenticated identities) or full handshake.
- Ensures forward secrecy is maintained over long-duration flights.
- Reduces cryptanalysis window for any single session key.

### 7. Multi-Hop Ground Relay

In an operational ground segment, a relay or mission-control node might sit between flight computers and user interface stations.

**Current Status:**
- This project uses a single hop (Bob→Alice) for clarity.
- A simple TCP relay could be inserted while keeping the end-to-end encrypted channel unchanged.
- The relay would only ever see ciphertext and metadata (not plaintext telemetry).

**Implementation Considerations:**
- Add intermediate relay node that forwards encrypted frames without decryption.
- Maintains end-to-end encryption between aircraft and final ground station.
- Relay only handles routing and forwarding based on connection metadata.
- Supports realistic ground segment architectures with multiple control centers or regional stations.