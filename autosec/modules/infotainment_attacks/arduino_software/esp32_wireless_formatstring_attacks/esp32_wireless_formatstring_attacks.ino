#include <BluetoothSerial.h>
#include <WiFi.h>

// Author: Michael Weichenrieder

// Board: ESP32 Dev Module
// USB Port <-> Host PC

BluetoothSerial SerialBT;
int bluetoothRunning = 0;


void setup() {
  // Start serial connection and enable wifi
  Serial.begin(9600);
  WiFi.mode(WIFI_AP);
}

void setBluetoothName(String name) {
  // Stop bluetooth if running
  if(bluetoothRunning) {
    SerialBT.end();
  }

  // Start bluetooth with new name
  SerialBT.begin(name);
  bluetoothRunning = 1;
}

void setWiFiName(String name) {
  // Start wifi with new name
  char buf[name.length() + 1];
  name.toCharArray(buf, name.length() + 1);
  WiFi.softAP(buf, NULL);
}

void loop() {
  if(Serial.available()) {
    // Read line from serial
    String read = Serial.readStringUntil('\n');

    // Set bluetooth and wifi name
    setBluetoothName(read);
    setWiFiName(read);

    // Send confirmation
    Serial.println(read);
  }
}
