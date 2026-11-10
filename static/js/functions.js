// =====================================================
// ESP32 RFID MONITORING SYSTEM
// External JavaScript File
// =====================================================


// =====================================================
// GLOBAL VARIABLES
// =====================================================

let allLogs = [];
let allCards = [];
let editingCardUID = null;


// =====================================================
// UPDATE CURRENT DATE
// =====================================================

function updateDate() {

    const dateElement = document.getElementById("current-date");

    if (!dateElement) return;

    const now = new Date();

    dateElement.textContent = now.toLocaleDateString(
        "en-PH",
        {
            year: "numeric",
            month: "long",
            day: "numeric"
        }
    );

}


// =====================================================
// CHECK FLASK API CONNECTION
// =====================================================

async function checkAPIStatus() {

    const statusElement = document.getElementById("api-status");

    if (!statusElement) return;

    try {

        const response = await fetch("/api/status");

        if (!response.ok) {
            throw new Error("API unavailable");
        }

        statusElement.className = "api-status online";

        statusElement.innerHTML =
            '<span class="status-dot"></span>' +
            'System Online';

    } catch (error) {

        console.error("API connection error:", error);

        statusElement.className = "api-status offline";

        statusElement.innerHTML =
            '<span class="status-dot"></span>' +
            'System Offline';

    }

}


// =====================================================
// FETCH RFID STATISTICS
// =====================================================

async function loadStatistics() {

    try {

        const response = await fetch(
            "/api/rfid/statistics"
        );

        if (!response.ok) {
            throw new Error("Statistics unavailable");
        }

        const data = await response.json();

        if (!data.success) {
            throw new Error("Statistics request failed");
        }

        const stats = data.statistics;

        document.getElementById("total-scans")
            .textContent = stats.total_scans;

        document.getElementById("authorized-scans")
            .textContent = stats.authorized_scans;

        document.getElementById("unauthorized-scans")
            .textContent = stats.unauthorized_scans;

    } catch (error) {

        console.error("Statistics error:", error);

    }

}


// =====================================================
// FETCH RFID SCAN HISTORY
// =====================================================

async function loadLogs() {

    try {

        const response = await fetch(
            "/api/rfid/logs?limit=1000"
        );

        if (!response.ok) {
            throw new Error("Unable to retrieve logs");
        }

        const data = await response.json();

        if (!data.success) {
            throw new Error("Log request failed");
        }

        allLogs = data.logs;

        renderLogs();

    } catch (error) {

        console.error("RFID logs error:", error);

        document.getElementById("logs-table").innerHTML = `
            <tr>
                <td colspan="4" class="empty-state">
                    Unable to load RFID records.
                </td>
            </tr>
        `;

    }

}


// =====================================================
// DISPLAY RFID SCAN HISTORY
// =====================================================

function renderLogs() {

    const table = document.getElementById("logs-table");

    if (!table) return;

    const searchValue = document.getElementById(
        "search-input"
    ).value.toUpperCase();

    const selectedStatus = document.getElementById(
        "status-filter"
    ).value;

    const filteredLogs = allLogs.filter(log => {

        const matchesUID =
            log.card_uid.toUpperCase().includes(searchValue);

        const matchesStatus =
            selectedStatus === "all" ||
            log.status === selectedStatus;

        return matchesUID && matchesStatus;

    });


    if (filteredLogs.length === 0) {

        table.innerHTML = `
            <tr>
                <td colspan="4" class="empty-state">
                    No RFID records found.
                </td>
            </tr>
        `;

        document.getElementById("record-count")
            .textContent = "Showing 0 records";

        return;

    }


    table.innerHTML = filteredLogs.map(log => {

        const statusClass =
            log.status === "authorized"
                ? "authorized"
                : "unauthorized";

        const statusLabel =
            log.status === "authorized"
                ? "AUTHORIZED"
                : "UNAUTHORIZED";

        const formattedDate =
            new Date(log.timestamp).toLocaleString(
                "en-PH",
                {
                    year: "numeric",
                    month: "short",
                    day: "2-digit",
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit",
                    hour12: true
                }
            );

        return `
            <tr>

                <td>#${log.id}</td>

                <td class="uid-cell">
                    ${escapeHTML(log.card_uid)}
                </td>

                <td>
                    <span class="status-badge ${statusClass}">
                        ${statusLabel}
                    </span>
                </td>

                <td>
                    ${escapeHTML(formattedDate)}
                </td>

            </tr>
        `;

    }).join("");


    document.getElementById("record-count").textContent =
        `Showing ${filteredLogs.length} of ${allLogs.length} records`;

}


// =====================================================
// ESCAPE HTML CONTENT
// =====================================================

function escapeHTML(value) {

    return String(value).replace(
        /[&<>"']/g,
        character => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#039;"
        })[character]
    );

}


// =====================================================
// RFID CARD MANAGEMENT
// =====================================================


// =====================================================
// LOAD REGISTERED RFID CARDS
// =====================================================

async function loadCards() {

    try {

        const response = await fetch("/api/rfid/cards");

        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(data.message || "Unable to load cards");
        }

        allCards = data.cards;

        renderCards();

    } catch (error) {

        console.error("Card loading error:", error);

        document.getElementById("cards-table").innerHTML = `
            <tr>
                <td colspan="5" class="empty-state">
                    Unable to load registered cards.
                </td>
            </tr>
        `;

    }

}


// =====================================================
// DISPLAY REGISTERED RFID CARDS
// =====================================================

function renderCards() {

    const table = document.getElementById("cards-table");

    if (!table) return;

    const searchValue = document.getElementById(
        "card-search"
    ).value.toLowerCase();

    const selectedStatus = document.getElementById(
        "card-status-filter"
    ).value;


    const filteredCards = allCards.filter(card => {

        const matchesSearch =
            card.card_uid.toLowerCase().includes(searchValue) ||
            card.cardholder_name.toLowerCase().includes(searchValue);

        const matchesStatus =
            selectedStatus === "all" ||
            card.status === selectedStatus;

        return matchesSearch && matchesStatus;

    });


    if (filteredCards.length === 0) {

        table.innerHTML = `
            <tr>
                <td colspan="5" class="empty-state">
                    No registered cards found.
                </td>
            </tr>
        `;

        document.getElementById("card-record-count")
            .textContent = `Showing 0 of ${allCards.length} cards`;

        return;

    }


    table.innerHTML = filteredCards.map(card => {

        const statusClass =
            card.status === "active"
                ? "authorized"
                : "unauthorized";

        const statusLabel = card.status.toUpperCase();

        const actionLabel =
            card.status === "active"
                ? "Deactivate"
                : "Activate";

        const nextStatus =
            card.status === "active"
                ? "inactive"
                : "active";


        return `
            <tr>

                <td class="uid-cell">
                    ${escapeHTML(card.card_uid)}
                </td>

                <td>
                    ${escapeHTML(card.cardholder_name)}
                </td>

                <td>
                    <span class="status-badge ${statusClass}">
                        ${statusLabel}
                    </span>
                </td>

                <td>
                    ${escapeHTML(formatDate(card.created_at))}
                </td>

                <td>

                    <div class="action-buttons">

                        <button
                            class="edit-button"
                            onclick="editRFIDCard('${escapeHTML(card.card_uid)}')">
                            Edit
                        </button>

                        <button
                            class="toggle-button"
                            onclick="toggleCardStatus('${escapeHTML(card.card_uid)}', '${nextStatus}')">
                            ${actionLabel}
                        </button>

                        <button
                            class="delete-button"
                            onclick="deleteRFIDCard('${escapeHTML(card.card_uid)}')">
                            Delete
                        </button>

                    </div>

                </td>

            </tr>
        `;

    }).join("");


    document.getElementById("card-record-count")
        .textContent =
            `Showing ${filteredCards.length} of ${allCards.length} cards`;

}


// =====================================================
// OPEN REGISTRATION FORM
// =====================================================

function openRegistrationForm() {

    editingCardUID = null;

    document.getElementById("form-title")
        .textContent = "Register RFID Card";

    document.getElementById("card-uid").value = "";

    document.getElementById("cardholder-name").value = "";

    document.getElementById("card-uid").disabled = false;

    document.getElementById("registration-form")
        .style.display = "block";

}


// =====================================================
// CLOSE REGISTRATION FORM
// =====================================================

function closeRegistrationForm() {

    editingCardUID = null;

    document.getElementById("registration-form")
        .style.display = "none";

}


// =====================================================
// REGISTER OR UPDATE RFID CARD
// =====================================================

async function saveRFIDCard() {

    const uid = document.getElementById("card-uid")
        .value.trim().toUpperCase();

    const name = document.getElementById("cardholder-name")
        .value.trim();


    if (!uid || !name) {

        alert("Please enter the RFID UID and cardholder name.");

        return;

    }


    const isEditing = editingCardUID !== null;

    const url = isEditing
        ? `/api/rfid/cards/${encodeURIComponent(editingCardUID)}`
        : "/api/rfid/cards";

    const method = isEditing ? "PUT" : "POST";


    try {

        const response = await fetch(url, {

            method: method,

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({

                card_uid: uid,

                cardholder_name: name

            })

        });


        const data = await response.json();


        if (!response.ok || !data.success) {

            alert(data.message || "Unable to save RFID card.");

            return;

        }


        alert(data.message);

        closeRegistrationForm();

        await loadCards();

        await loadStatistics();


    } catch (error) {

        console.error("Save card error:", error);

        alert("Unable to connect to the Flask server.");

    }

}


// =====================================================
// EDIT RFID CARD
// =====================================================

function editRFIDCard(uid) {

    const card = allCards.find(
        item => item.card_uid === uid
    );

    if (!card) return;

    editingCardUID = uid;

    document.getElementById("form-title")
        .textContent = "Update Cardholder Information";

    document.getElementById("card-uid").value = card.card_uid;

    document.getElementById("card-uid").disabled = true;

    document.getElementById("cardholder-name").value =
        card.cardholder_name;

    document.getElementById("registration-form")
        .style.display = "block";

}


// =====================================================
// ACTIVATE OR DEACTIVATE RFID CARD
// =====================================================

async function toggleCardStatus(uid, status) {

    const action = status === "active"
        ? "activate"
        : "deactivate";


    if (!confirm(`Are you sure you want to ${action} this card?`)) {
        return;
    }


    try {

        const response = await fetch(
            `/api/rfid/cards/${encodeURIComponent(uid)}/status`,
            {

                method: "PATCH",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    status: status
                })

            }
        );


        const data = await response.json();


        if (!response.ok || !data.success) {

            alert(data.message || "Unable to update card status.");

            return;

        }


        alert(data.message);

        await loadCards();

        await loadStatistics();


    } catch (error) {

        console.error("Card status error:", error);

        alert("Unable to update card status.");

    }

}


// =====================================================
// DELETE RFID CARD
// =====================================================

async function deleteRFIDCard(uid) {

    if (!confirm(
        "Are you sure you want to delete this RFID card?"
    )) {
        return;
    }


    try {

        const response = await fetch(
            `/api/rfid/cards/${encodeURIComponent(uid)}`,
            {
                method: "DELETE"
            }
        );


        const data = await response.json();


        if (!response.ok || !data.success) {

            alert(data.message || "Unable to delete RFID card.");

            return;

        }


        alert(data.message);

        await loadCards();

        await loadStatistics();


    } catch (error) {

        console.error("Delete card error:", error);

        alert("Unable to delete RFID card.");

    }

}


// =====================================================
// FORMAT DATE
// =====================================================

function formatDate(timestamp) {

    return new Date(timestamp).toLocaleDateString(
        "en-PH",
        {
            year: "numeric",
            month: "short",
            day: "numeric"
        }
    );

}


// =====================================================
// REFRESH DASHBOARD
// =====================================================

async function refreshDashboard() {

    await Promise.all([

        checkAPIStatus(),

        loadStatistics(),

        loadLogs(),

        loadCards()

    ]);

}


// =====================================================
// INITIALIZE DASHBOARD
// =====================================================

document.addEventListener("DOMContentLoaded", function () {

    updateDate();

    refreshDashboard();

    // Automatically refresh dashboard every 5 seconds.
    setInterval(refreshDashboard, 5000);

});