#include <Keyboard.h>

// Author: Michael Weichenrieder

// Board: Arduino Zero (Programming Port)
// Native Port <-> Target Device
// Programming Port <-> Host PC
// IMPORTANT: Connect the target device first for usb host selection (if there is no power on native usb, the target device gets host)

const int CMD_LAYOUT = 0;
const int CMD_KEYSTROKES = 1;
const int CMD_PRESS = 2;
const int CMD_RELEASE = 3;
const int CMD_WRITE = 4;

int isGermanLayout = 0;


void setup() {
  // Start serial connection and keyboard library
  Serial.begin(9600);
  Keyboard.begin();
}

void setGermanLayout(int german) {
  if(german != isGermanLayout) {
    // Restart keyboard library with new layout
    Keyboard.end();
    Keyboard.begin(german ? KeyboardLayout_de_DE : KeyboardLayout_en_US);
    isGermanLayout = german;
  }
}

void executeCommand(String command) {
    // Split into prefix and value
    int split = command.indexOf(" ");
    if(split == -1) {
      return;
    }
    int prefix = command.substring(0, split).toInt();
    String value = command.substring(split + 1);
    if(value.length() == 0) {
      return;
    }

    // Switch by prefix
    switch(prefix) {
      case CMD_LAYOUT:
        // Set keyboard layout
        setGermanLayout(value.equals("de"));
        break;
      case CMD_KEYSTROKES:
        // Send keystrokes
        Keyboard.print(value);
        break;
      case CMD_PRESS:
        // Send key press
        Keyboard.press(value.charAt(0));
        break;
      case CMD_RELEASE:
        // Send key release
        Keyboard.release(value.charAt(0));
        break;
      case CMD_WRITE:
        // Send key release
        Keyboard.write(value.charAt(0));
        break;
    }
}

void loop() {
  if(Serial.available()) {
    // Read line from serial
    String read = Serial.readStringUntil('\n');

    // Execute command
    executeCommand(read);

    // Send confirmation
    Serial.println(read);
  }
}
