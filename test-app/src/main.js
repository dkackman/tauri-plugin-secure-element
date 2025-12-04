// Import from the copied plugin files
import { generateSecureKey, ping, signData } from "./lib/index.js";

console.log("Plugin imported:", { generateSecureKey, signData, ping });

// Test ping command to verify plugin is working
window.testPlugin = async () => {
  try {
    console.log("Testing ping command...");
    const result = await ping("test");
    console.log("Ping result:", result);
    return result;
  } catch (error) {
    console.error("Ping error:", error);
    throw error;
  }
};

let generateKeyBtn;
let keyStatusEl;
let signInputEl;
let signOutputEl;

/**
 * Converts a Uint8Array to a hexadecimal string
 * @param {Uint8Array} bytes - The bytes to convert
 * @returns {string} Hexadecimal string representation
 */
function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Converts a string to a Uint8Array using UTF-8 encoding
 * @param {string} str - The string to convert
 * @returns {Uint8Array} The encoded bytes
 */
function stringToUint8Array(str) {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}

async function handleGenerateKey() {
  try {
    console.log("handleGenerateKey called");
    console.log("generateSecureKey function:", generateSecureKey);
    keyStatusEl.textContent = "Generating secure key...";
    generateKeyBtn.disabled = true;

    console.log("Calling generateSecureKey...");
    const result = await generateSecureKey();
    console.log("generateSecureKey completed, result:", result);

    keyStatusEl.textContent = "✓ Secure key generated successfully!";
    keyStatusEl.style.color = "#4caf50";
  } catch (error) {
    console.error("Error in handleGenerateKey:", error);
    console.error("Error stack:", error.stack);
    keyStatusEl.textContent = `✗ Error: ${error.message || error}`;
    keyStatusEl.style.color = "#f44336";
  } finally {
    generateKeyBtn.disabled = false;
  }
}

async function handleSign(e) {
  e.preventDefault();

  const inputValue = signInputEl.value.trim();
  if (!inputValue) {
    signOutputEl.textContent = "Please enter data to sign";
    return;
  }

  try {
    console.log("handleSign called with input:", inputValue);
    signOutputEl.textContent = "Signing...";

    // Convert string to Uint8Array
    const dataToSign = stringToUint8Array(inputValue);
    console.log("Data to sign (Uint8Array):", dataToSign);

    // Sign the data
    console.log("Calling signData with:", dataToSign);
    console.log("signData function:", signData);
    const signedData = await signData(dataToSign);
    console.log("signData completed, result:", signedData);

    // Convert result to hex string
    const hexResult = bytesToHex(signedData);
    console.log("Hex result:", hexResult);

    signOutputEl.textContent = hexResult;
    signOutputEl.style.color = "";
  } catch (error) {
    console.error("Error in handleSign:", error);
    signOutputEl.textContent = `Error: ${error}`;
    signOutputEl.style.color = "#f44336";
  }
}

window.addEventListener("DOMContentLoaded", () => {
  generateKeyBtn = document.querySelector("#generate-key-btn");
  keyStatusEl = document.querySelector("#key-status");
  signInputEl = document.querySelector("#sign-input");
  signOutputEl = document.querySelector("#sign-output");

  generateKeyBtn.addEventListener("click", handleGenerateKey);
  document.querySelector("#sign-form").addEventListener("submit", handleSign);
});
