#include <SPI.h>
#include <MFRC522.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>

// ========================================
// 1. WI-FI CONFIGURATION
// ========================================

const char* ssid = "AL-RAJI";
const char* password = "";

const char* serverURL =
  "http://10.210.208.251:5000/api/rfid/scan";

const char* serverIP = "10.210.208.251";

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
// 4. AUTHORIZATION RESULT
// ========================================

enum AuthorizationResult {
  AUTHORIZED,
  UNAUTHORIZED,
  SERVER_ERROR
};

// ========================================
// 5. FUNCTION DECLARATIONS
// ========================================

void connectWiFi();
void testFlaskConnection();
String getCardUID();
AuthorizationResult sendToServer(const String& uid);
void indicateAuthorized();
void indicateUnauthorized();
void indicateServerError();
void clearIndicators();

// ========================================
// 6. SETUP
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

  clearIndicators();

  Serial.println();
  Serial.println("================================");
  Serial.println(" ESP32 RFID SYSTEM - PHASE 8");
  Serial.println(" SERVER-SIDE AUTHORIZATION");
  Serial.println("================================");

  connectWiFi();
  testFlaskConnection();

  Serial.println();
  Serial.println("RFID Reader initialized.");
  Serial.println("Authorization is handled by Flask.");
  Serial.println("Please scan your RFID card...");
}

// ========================================
// 7. MAIN LOOP
// ========================================

void loop() {

  // Reconnect to Wi-Fi when disconnected.
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

  // Ask the Flask server to decide authorization.
  AuthorizationResult result = sendToServer(cardUID);

  if (result == AUTHORIZED) {

    Serial.println("ACCESS GRANTED BY SERVER!");
    indicateAuthorized();

  } else if (result == UNAUTHORIZED) {

    Serial.println("ACCESS DENIED BY SERVER!");
    indicateUnauthorized();

  } else {

    // Fail closed: no server response means no access grant.
    Serial.println("AUTHORIZATION UNAVAILABLE.");
    Serial.println("ACCESS NOT GRANTED.");
    indicateServerError();

  }

  Serial.println("--------------------------------");

  delay(1500);
  clearIndicators();

  // Finish communication with the RFID card.
  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1();

  delay(500);
}

// ========================================
// 8. WI-FI CONNECTION
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
// 9. GET RFID CARD UID
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
// 10. SEND UID TO FLASK AND READ DECISION
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
// 11. AUTHORIZED CARD INDICATION
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
// 12. UNAUTHORIZED CARD INDICATION
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
// 13. SERVER / NETWORK ERROR INDICATION
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
// 14. TURN OFF ALL INDICATORS
// ========================================

void clearIndicators() {

  digitalWrite(GREEN_LED, LOW);
  digitalWrite(RED_LED, LOW);
  digitalWrite(BUZZER, LOW);
}

// ========================================
// 15. TEST FLASK SERVER CONNECTION
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
