# ITO5163 Assessment 2
# Student ID: 35619694
# Student Name: Nicholas Battle

"""
Telemetry Stream Generator
Provides telemetry data from two sources:
1. Simulated ADS-C data for controlled demos
2. Real ADS-C data from CSV files (OpenSky Network dataset)
Simulated mode generates realistic aircraft telemetry with predictable patterns.
Real mode streams actual aerospace data from preprocessed CSV files.
"""
import random
import time
import csv
import re
from datetime import datetime
from pathlib import Path


class TelemetryStream:
    """
    Generates simulated aircraft telemetry data.
    """
    
    # Sample aircraft registrations
    AIRCRAFT_REGISTRATIONS = [
        "N790AN", "N123BA", "G-EUXA", "VH-OEF", "B-2032",
        "D-AIHF", "F-HPJA", "C-GTSD", "JA8942", "HL7733"
    ]
    
    # Sample route waypoints (lat, lon)
    WAYPOINTS = [
        (51.3940, -33.6191),  # Mid-Atlantic
        (48.8566, -2.3522),   # Near France
        (40.7128, -74.0060),  # New York area
        (35.6762, 139.6503),  # Tokyo area
        (-33.8688, 151.2093), # Sydney area
    ]
    
    def __init__(self, registration=None, initial_position=None):
        """
        Initialize telemetry stream for an aircraft.
        
        Args:
            registration: Aircraft registration (e.g., "N790AN")
            initial_position: Tuple of (lat, lon) starting position
        """
        self.registration = registration or random.choice(self.AIRCRAFT_REGISTRATIONS)
        
        if initial_position:
            self.lat, self.lon = initial_position
        else:
            self.lat, self.lon = random.choice(self.WAYPOINTS)
        
        # Initial flight parameters
        self.alt_ft = random.randint(35000, 41000)
        self.speed_kt = random.randint(450, 550)
        self.heading = random.uniform(0, 360)
        self.wind_kt = random.uniform(50, 120)
        self.wind_dir = random.uniform(0, 360)
        self.temp_c = random.uniform(-65, -45)
        self.mach = random.uniform(0.80, 0.88)
        self.vertical_speed = random.uniform(-50, 50)
        
        # Movement parameters
        self.lat_rate = random.uniform(-0.001, 0.001)
        self.lon_rate = random.uniform(-0.001, 0.001)
    
    def get_next_frame(self):
        """
        Generate next telemetry frame with updated position and parameters.
        
        Returns:
            dict: Telemetry data frame
        """
        # Update position (simulate movement)
        self.lat += self.lat_rate
        self.lon += self.lon_rate
        
        # Simulate realistic parameter variations
        self.alt_ft += random.randint(-100, 100)
        self.alt_ft = max(30000, min(42000, self.alt_ft))
        
        self.speed_kt += random.uniform(-5, 5)
        self.speed_kt = max(400, min(600, self.speed_kt))
        
        self.heading += random.uniform(-2, 2)
        self.heading = self.heading % 360
        
        self.wind_kt += random.uniform(-5, 5)
        self.wind_kt = max(0, min(150, self.wind_kt))
        
        self.temp_c += random.uniform(-1, 1)
        self.temp_c = max(-70, min(-40, self.temp_c))
        
        self.mach += random.uniform(-0.01, 0.01)
        self.mach = max(0.75, min(0.90, self.mach))
        
        self.vertical_speed += random.uniform(-10, 10)
        self.vertical_speed = max(-200, min(200, self.vertical_speed))
        
        # Create telemetry frame with ADS-C fields matching CSV structure
        frame = {
            "Registration": self.registration,
            "Latitude": round(self.lat, 4),
            "Longitude": round(self.lon, 4),
            "Altitude": int(self.alt_ft),
            "Timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "Wind speed": round(self.wind_kt, 1),
            "Temperature": round(self.temp_c, 1),
            "Position accuracy": "<0.05 nm",
            "NAV redundancy": "OK",
            "TCAS": "OK",
            "Mach speed": round(self.mach, 4),
            "Vertical speed": round(self.vertical_speed, 1),
            "ETA": ""
        }
        
        return frame
    
    def get_batch_frames(self, count=10):
        """
        Generate multiple telemetry frames.
        
        Args:
            count: Number of frames to generate
            
        Returns:
            list: List of telemetry frames
        """
        return [self.get_next_frame() for _ in range(count)]
    
    @staticmethod
    def create_random_stream():
        """
        Create a telemetry stream with random aircraft and position.
        
        Returns:
            TelemetryStream: New telemetry stream instance
        """
        return TelemetryStream()
    
    @staticmethod
    def create_predefined_stream(scenario="transatlantic"):
        """
        Create a telemetry stream with predefined scenario.
        
        Args:
            scenario: Scenario name ("transatlantic", "transpacific", "domestic")
            
        Returns:
            TelemetryStream: New telemetry stream instance
        """
        scenarios = {
            "transatlantic": {
                "registration": "N790AN",
                "position": (51.3940, -33.6191),
            },
            "transpacific": {
                "registration": "JA8942",
                "position": (35.6762, 139.6503),
            },
            "domestic": {
                "registration": "N123BA",
                "position": (40.7128, -74.0060),
            }
        }
        
        config = scenarios.get(scenario, scenarios["transatlantic"])
        return TelemetryStream(
            registration=config["registration"],
            initial_position=config["position"]
        )


class TelemetryLogger:
    """
    Logs received telemetry data to console or file.
    """
    
    def __init__(self, log_file=None):
        """
        Initialize telemetry logger.
        
        Args:
            log_file: Optional file path to write logs
        """
        self.log_file = log_file
        self.frame_count = 0
    
    def log_frame(self, frame):
        """
        Log a telemetry frame.
        
        Args:
            frame: dict with telemetry data
        """
        self.frame_count += 1
        
        # Build log entry with core fields using proper CSV column names
        log_entry = (
            f"[{frame['Timestamp']}] {frame['Registration']}: "
            f"Lat={frame['Latitude']}, Lon={frame['Longitude']}, "
            f"Alt={frame['Altitude']}ft"
        )
        
        # Add optional fields if present and meaningful
        if frame.get('Wind speed') and frame['Wind speed'] > 0:
            log_entry += f", Wind={frame['Wind speed']}kt"
        if frame.get('Temperature') and frame['Temperature'] != -50.0:
            log_entry += f", Temp={frame['Temperature']}°C"
        if frame.get('Mach speed'):
            log_entry += f", Mach={frame['Mach speed']}"
        if frame.get('Vertical speed'):
            log_entry += f", V/S={frame['Vertical speed']}ft/min"
        
        # Add ADS-C specific fields if present and not empty
        if frame.get('Position accuracy'):
            log_entry += f", PosAcc={frame['Position accuracy']}"
        if frame.get('NAV redundancy'):
            log_entry += f", NAV={frame['NAV redundancy']}"
        if frame.get('TCAS'):
            log_entry += f", TCAS={frame['TCAS']}"
        if frame.get('ETA'):
            log_entry += f", ETA={frame['ETA']}"
        
        print(log_entry)
        
        if self.log_file:
            with open(self.log_file, 'a') as f:
                f.write(log_entry + '\n')
    
    def get_statistics(self):
        """
        Get logging statistics.
        
        Returns:
            dict: Statistics about logged frames
        """
        return {
            "frames_logged": self.frame_count
        }


class RealTelemetryStream:
    """
    Streams real ADS-C telemetry data from CSV files.
    
    This class reads preprocessed ADS-C data from OpenSky Network
    and streams it frame-by-frame for transmission.
    """
    
    def __init__(self, csv_file):
        """
        Initialize real telemetry stream from CSV.
        
        Args:
            csv_file: Path to CSV file with ADS-C data
        """
        self.csv_file = Path(csv_file)
        self.frames = []
        self.current_index = 0
        self.load_csv()
    
    def load_csv(self):
        """
        Load ADS-C data from CSV file.
        
        Handles CSV format with columns:
        Registration, Latitude, Longitude, Altitude, Timestamp,
        Wind speed, Temperature, Position accuracy, NAV redundancy, TCAS, ETA
        """
        if not self.csv_file.exists():
            raise FileNotFoundError(f"ADS-C CSV file not found: {self.csv_file}")
        
        with open(self.csv_file, 'r', encoding='utf-8') as f:
            # Read CSV with headers
            reader = csv.DictReader(f)
            for row in reader:
                # Parse values that include units (e.g., "38000.0 ft") into numbers
                alt_str = row.get("Altitude", "0 ft")
                alt_match = re.search(r'([-\d.]+)', alt_str)
                alt_value = float(alt_match.group(1)) if alt_match else 0.0
                
                # Extract wind speed from "85.0 kt" format (may be empty)
                wind_str = row.get("Wind speed", "")
                if wind_str.strip():
                    wind_match = re.search(r'([-\d.]+)', wind_str)
                    wind_value = float(wind_match.group(1)) if wind_match else 0.0
                else:
                    wind_value = 0.0
                
                # Extract temperature from "-59.0 C" format (may be empty)
                temp_str = row.get("Temperature", "")
                if temp_str.strip():
                    temp_match = re.search(r'([-\d.]+)', temp_str)
                    temp_value = float(temp_match.group(1)) if temp_match else -50.0
                else:
                    temp_value = -50.0
                
                # Extract Mach speed (numeric value)
                mach_str = row.get("Mach speed", "0.8")
                try:
                    mach_value = float(mach_str)
                except ValueError:
                    mach_value = 0.8
                
                # Extract vertical speed from "16.0 ft/min" format (may be empty)
                vs_str = row.get("Vertical speed", "")
                if vs_str.strip():
                    vs_match = re.search(r'([-\d.]+)', vs_str)
                    vs_value = float(vs_match.group(1)) if vs_match else 0.0
                else:
                    vs_value = 0.0
                
                # construct clean telemetry frame from parsed values
                frame = {
                    "Registration": row["Registration"],
                    "Latitude": float(row["Latitude"]),
                    "Longitude": float(row["Longitude"]),
                    "Altitude": int(alt_value),
                    "Timestamp": row["Timestamp"],
                    "Wind speed": wind_value,
                    "Temperature": temp_value,
                    "Position accuracy": row.get("Position accuracy", ""),
                    "NAV redundancy": row.get("NAV redundancy", ""),
                    "TCAS": row.get("TCAS", ""),
                    "Mach speed": mach_value,
                    "Vertical speed": vs_value,
                    "ETA": row.get("ETA", "")
                }
                self.frames.append(frame)
        
        if not self.frames:
            raise ValueError(f"No valid frames found in {self.csv_file}")
        
        print(f"[RealTelemetry] Loaded {len(self.frames)} frames from {self.csv_file}")
    
    def get_next_frame(self):
        """
        Get next telemetry frame from CSV.
        
        Returns:
            dict: Telemetry data frame
        """
        if self.current_index >= len(self.frames):
            self.current_index = 0
        
        frame = self.frames[self.current_index].copy()
        self.current_index += 1
        
        return frame
    
    def get_batch_frames(self, count=10):
        """
        Get multiple telemetry frames.
        
        Args:
            count: Number of frames to retrieve
            
        Returns:
            list: List of telemetry frames
        """
        return [self.get_next_frame() for _ in range(min(count, len(self.frames)))]
    
    def reset(self):
        """
        Reset to beginning of CSV data.
        """
        self.current_index = 0
    
    def get_total_frames(self):
        """
        Get total number of frames available.
        
        Returns:
            int: Total frame count
        """
        return len(self.frames)