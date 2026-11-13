#include <SPI.h>
#include <MFRC522.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <ESP32Servo.h>

// ========================================
// 1. WI-FI CONFIGURATION
// ========================================

const char* ssid = "AL-RAJI";
const char* password = "";

const char* serverURL =
  "http://10.103.22.251:5000/api/rfid/scan";

const char* serverIP = "10.103.22.251";

// Must match DEVICE_API_KEY in app.py.
const char* DEVICE_API_KEY = "f9753aeeb289bf822555b5aa287c4dd57de6675052c1f5daec0c4e3ce1bcba5c";

// ========================================
// 2. RFID CONFIGURATION
// ========================================

#define SS_PIN  5
#define RST_PIN 22

MFRC522 rfid(SS_PIN, RST_PIN);

// The ESP32 no longer contains a hardcoded authorized UID.
// Flask checks the UID against the rfid_cards database.

// ========================================
// 3. LED AND BUZZER CONFIGURATION
// ========================================

#define GREEN_LED 25
#define RED_LED   27
#define BUZZER    26

// ========================================
// 4. SG90 DOOR-LOCK SERVO CONFIGURATION
// ========================================

#define SERVO_PIN 13

// Adjust these angles to match the physical latch mechanism.
const int LOCKED_ANGLE = 0;
const int UNLOCKED_ANGLE = 90;
const unsigned long DOOR_UNLOCK_DURATION_MS = 5000;

Servo doorServo;
bool doorIsUnlocked = false;
unsigned long doorUnlockStartedAt = 0;

// ========================================
// 5. AUTHORIZATION RESULT
// ========================================

enum AuthorizationResult {
  AUTHORIZED,
  UNAUTHORIZED,
  SERVER_ERROR
};

// ========================================
// 6. FUNCTION DECLARATIONS
// ========================================

void connectWiFi();
void testFlaskConnection();
String getCardUID();
AuthorizationResult sendToServer(const String& uid);
void indicateAuthorized();
void indicateUnauthorized();
void indicateServerError();
void clearIndicators();
void unlockDoor();
void updateDoorLock();

// ========================================
// 7. SETUP
// ========================================

void setup() {

  Serial.begin(115200);
  delay(1000);

  // Initialize SPI and RFID reader.
  SPI.begin(18, 19, 23, SS_PIN);
  rfid.PCD_Init();

  // Initialize output pins.
  pinMode(GREEN_LED, OUTPUT);
  pinMode(RED_LED, OUTPUT);
  pinMode(BUZZER, OUTPUT);

  // Initialize the SG90 and command the door to the locked position.
  doorServo.setPeriodHertz(50);
  doorServo.attach(SERVO_PIN, 500, 2400);
  doorServo.write(LOCKED_ANGLE);
  delay(500);
  doorIsUnlocked = false;

  clearIndicators();

  Serial.println();
  Serial.println("================================");
  Serial.println(" ESP32 RFID SYSTEM - PHASE 9");
  Serial.println(" RFID + SG90 DOOR LOCK");
  Serial.println("================================");

  connectWiFi();
  testFlaskConnection();

  Serial.println();
  Serial.println("RFID Reader initialized.");
  Serial.println("Authorization is handled by Flask.");
  Serial.println("Please scan your RFID card...");
}

// ========================================
// 8. MAIN LOOP
// ========================================

void loop() {

  // Service the automatic relock timer on every pass.
  updateDoorLock();

  // Do not process another card while the door is unlocked.
  // This keeps blocking network requests from delaying the relock.
  if (doorIsUnlocked) {
    delay(20);
    return;
  }

  // Reconnect to Wi-Fi when disconnected. The door remains locked.
  if (WiFi.status() != WL_CONNECTED) {

    Serial.println("Wi-Fi disconnected. Reconnecting...");
    connectWiFi();

    if (WiFi.status() != WL_CONNECTED) {
      indicateServerError();
      delay(1000);
      return;
    }
  }

  // Wait until a new RFID card is presented.
  if (!rfid.PICC_IsNewCardPresent()) {
    delay(50);
    return;
  }

  if (!rfid.PICC_ReadCardSerial()) {
    return;
  }

  Serial.println();
  Serial.println("================================");
  Serial.println("RFID CARD DETECTED!");
  Serial.println("================================");

  String cardUID = getCardUID();

  Serial.print("Card UID: ");
  Serial.println(cardUID);

  // Flask remains the authority. No local UID allowlist is used.
  AuthorizationResult result = sendToServer(cardUID);

  // Finish communication with the RFID card before handling the result.
  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1();

  if (result == AUTHORIZED) {

    Serial.println("ACCESS GRANTED BY SERVER!");
    indicateAuthorized();
    unlockDoor();

  } else if (result == UNAUTHORIZED) {

    Serial.println("ACCESS DENIED BY SERVER!");
    indicateUnauthorized();

  } else {

    // Fail closed: a server/network error must never unlock the door.
    Serial.println("AUTHORIZATION UNAVAILABLE.");
    Serial.println("ACCESS NOT GRANTED.");
    indicateServerError();

  }

  Serial.println("--------------------------------");
  delay(20);
}

// ========================================
// 9. SG90 DOOR-LOCK CONTROL
// ========================================

void unlockDoor() {

  if (doorIsUnlocked) {
    return;
  }

  Serial.println("DOOR UNLOCKED: SG90 moving to unlock position.");
  doorServo.write(UNLOCKED_ANGLE);
  doorUnlockStartedAt = millis();
  doorIsUnlocked = true;

  Serial.println("Door will relock automatically after 5 seconds.");
}

void updateDoorLock() {

  if (!doorIsUnlocked) {
    return;
  }

  if (millis() - doorUnlockStartedAt >= DOOR_UNLOCK_DURATION_MS) {

    doorServo.write(LOCKED_ANGLE);
    doorIsUnlocked = false;

    Serial.println("DOOR RELOCKED: SG90 returned to locked position.");
  }
}

// ========================================
// 10. WI-FI CONNECTION
// ========================================

void connectWiFi() {

  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  Serial.print("Connecting to Wi-Fi");

  int attempts = 0;

  while (WiFi.status() != WL_CONNECTED && attempts < 40) {
    delay(500);
    Serial.print(".");
    attempts++;
  }

  Serial.println();

  if (WiFi.status() == WL_CONNECTED) {

    Serial.println("Wi-Fi connected successfully!");

    Serial.print("Network Name: ");
    Serial.println(WiFi.SSID());

    Serial.print("ESP32 IP Address: ");
    Serial.println(WiFi.localIP());

    Serial.print("Signal Strength: ");
    Serial.print(WiFi.RSSI());
    Serial.println(" dBm");

  } else {

    Serial.println("Wi-Fi connection failed!");
    Serial.println("Check the Wi-Fi name and password.");

  }
}

// ========================================
// 11. GET RFID CARD UID
// ========================================

String getCardUID() {

  String uid = "";

  for (byte i = 0; i < rfid.uid.size; i++) {

    if (rfid.uid.uidByte[i] < 0x10) {
      uid += "0";
    }

    uid += String(rfid.uid.uidByte[i], HEX);
  }

  uid.toUpperCase();
  return uid;
}

// ========================================
// 12. SEND UID TO FLASK AND READ DECISION
// ========================================

AuthorizationResult sendToServer(const String& uid) {

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("ERROR: Wi-Fi is disconnected.");
    return SERVER_ERROR;
  }

  WiFiClient client;
  HTTPClient http;

  http.setTimeout(5000);

  if (!http.begin(client, serverURL)) {
    Serial.println("ERROR: Could not initialize HTTP connection.");
    return SERVER_ERROR;
  }

  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-Device-Key", DEVICE_API_KEY);

  // Send only the UID. Flask must determine the card's status.
  String jsonPayload = "{\"uid\":\"" + uid + "\"}";

  Serial.println();
  Serial.println("Sending UID to Flask for authorization...");
  Serial.println("JSON Payload:");
  Serial.println(jsonPayload);

  int httpResponseCode = http.POST(jsonPayload);

  if (httpResponseCode <= 0) {

    Serial.print("HTTP Request Failed: ");
    Serial.println(http.errorToString(httpResponseCode));

    http.end();
    return SERVER_ERROR;
  }

  Serial.print("HTTP Response Code: ");
  Serial.println(httpResponseCode);

  String response = http.getString();

  Serial.println("Flask Server Response:");
  Serial.println(response);

  if (httpResponseCode != 200) {
    Serial.println("The server did not process the scan successfully.");
    http.end();
    return SERVER_ERROR;
  }

  // ArduinoJson is used to read Flask's JSON response.
  StaticJsonDocument<512> responseDocument;

  DeserializationError jsonError =
    deserializeJson(responseDocument, response);

  if (jsonError) {
    Serial.print("JSON parsing failed: ");
    Serial.println(jsonError.c_str());

    http.end();
    return SERVER_ERROR;
  }

  bool success = responseDocument["success"] | false;
  const char* status = responseDocument["status"] | "";

  const char* cardholder =
    responseDocument["cardholder"] | "Unknown";

  Serial.print("Cardholder: ");
  Serial.println(cardholder);

  bool duplicate = responseDocument["duplicate"] | false;

  if (duplicate) {
    Serial.println("Duplicate scan detected by server; log entry suppressed.");
  }

  http.end();

  if (!success) {
    Serial.println("The server reported that the scan failed.");
    return SERVER_ERROR;
  }

  if (strcmp(status, "authorized") == 0) {
    return AUTHORIZED;
  }

  if (strcmp(status, "unauthorized") == 0) {
    return UNAUTHORIZED;
  }

  Serial.println("Unexpected authorization status from server.");
  return SERVER_ERROR;
}

// ========================================
// 13. AUTHORIZED CARD INDICATION
// ========================================

void indicateAuthorized() {

  digitalWrite(RED_LED, LOW);
  digitalWrite(GREEN_LED, HIGH);

  // One short beep.
  digitalWrite(BUZZER, HIGH);
  delay(150);
  digitalWrite(BUZZER, LOW);
}

// ========================================
// 14. UNAUTHORIZED CARD INDICATION
// ========================================

void indicateUnauthorized() {

  digitalWrite(GREEN_LED, LOW);
  digitalWrite(RED_LED, HIGH);

  // Three warning beeps.
  for (int i = 0; i < 3; i++) {

    digitalWrite(BUZZER, HIGH);
    delay(150);

    digitalWrite(BUZZER, LOW);
    delay(150);
  }
}

// ========================================
// 15. SERVER / NETWORK ERROR INDICATION
// ========================================

void indicateServerError() {

  digitalWrite(GREEN_LED, LOW);

  // Red LED flashes twice to distinguish a server
  // or network problem from a normal card denial.
  for (int i = 0; i < 2; i++) {

    digitalWrite(RED_LED, HIGH);
    digitalWrite(BUZZER, HIGH);
    delay(350);

    digitalWrite(RED_LED, LOW);
    digitalWrite(BUZZER, LOW);
    delay(250);
  }
}

// ========================================
// 16. TURN OFF ALL INDICATORS
// ========================================

void clearIndicators() {

  digitalWrite(GREEN_LED, LOW);
  digitalWrite(RED_LED, LOW);
  digitalWrite(BUZZER, LOW);
}

// ========================================
// 17. TEST FLASK SERVER CONNECTION
// ========================================

void testFlaskConnection() {

  Serial.println();
  Serial.println("==============================");
  Serial.println(" TESTING FLASK HTTP CONNECTION");
  Serial.println("==============================");

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("ERROR: ESP32 is not connected to Wi-Fi.");
    return;
  }

  WiFiClient client;
  HTTPClient http;

  String testURL =
    "http://" + String(serverIP) + ":5000/api/status";

  http.setTimeout(5000);

  if (!http.begin(client, testURL)) {
    Serial.println("ERROR: Could not initialize HTTP connection.");
    return;
  }

  Serial.println("Sending HTTP GET request...");

  int responseCode = http.GET();

  if (responseCode > 0) {

    Serial.print("HTTP Response Code: ");
    Serial.println(responseCode);

    Serial.println("Flask Server Response:");
    Serial.println(http.getString());

    if (responseCode == 200) {
      Serial.println("FLASK CONNECTION SUCCESSFUL!");
    }

  } else {

    Serial.print("HTTP Connection Failed: ");
    Serial.println(http.errorToString(responseCode));

  }

  http.end();

  Serial.println("==============================");
}
