// Default relays if none are specified
const defaultRelays = [
    "wss://relay.damus.io",
    "wss://relay.primal.net",
    "wss://nos.lol",
    "wss://relay.snort.social",
    "wss://relay.nostr.band"
];

// Decode note1 from a bech32 string (Based on NIP-19)
function decodeNote1(input) {
    // Match only "nostr:note1" strings
    const note1Match = input.match(/nostr:note1\w+/);
    if (!note1Match) return null;

    const note1 = note1Match[0];
    // console.log("Decoding note1:", note1);

    try {
        // bech32.decode returns a *string* instead of throwing when it refuses, and defaults to a 90-character
        // limit — so the shape is checked before it is used, and the limit is raised for long references.
        const decoded = bech32.decode(note1.replace(/^nostr:/, ""), 1000);
        if (!decoded || typeof decoded !== "object" || !decoded.words) {
            throw new Error(String(decoded));
        }
        const bytes = bech32.fromWords(decoded.words);

        if (bytes.length !== 32) {
            throw new Error("Invalid nostr:note1 string. Incorrect byte length.");
        }

        const eventId = bytesToHex(bytes);
        // console.log(`Decoded note1 Event ID (Hex): ${eventId}`);
        return { eventId, note1String: note1 };
    } catch (error) {
        console.error("Failed to decode nostr:note1:", error);
        return null;
    }
}

/**
 * Decode an `nevent1` reference (NIP-19): an event id together with the relays the person sharing it
 * suggested, and optionally its author and kind.
 *
 * This is what most clients emit now, and the relay hints are the reason: a reader who is handed the
 * relays does not have to hope that one of the page's own relays happens to hold the note, which is the
 * slow path `note1` forces.
 */
function decodeNevent(input) {
    const match = String(input).match(/nostr:nevent1\w+/) || String(input).match(/\bnevent1\w+/);
    if (!match) return null;

    const reference = match[0];
    try {
        // an nevent is longer than a note1 (it carries relays), and BIP-173's 90-character default rejects
        // every one of them; the library reports that as a returned string, not an exception.
        const decoded = bech32.decode(reference.replace(/^nostr:/, ""), 1000);
        if (!decoded || typeof decoded !== "object" || !decoded.words) {
            throw new Error(String(decoded));
        }
        const bytes = bech32.fromWords(decoded.words);
        const decoder = new TextDecoder();

        let eventId = null;
        let author = null;
        let kind = null;
        const relays = [];

        // NIP-19 nevent is TLV: type 0 = 32-byte id, 1 = relay url, 2 = 32-byte author, 3 = kind
        let index = 0;
        while (index + 1 < bytes.length) {
            const type = bytes[index++];
            const length = bytes[index++];
            if (length === undefined || index + length > bytes.length) break;
            const value = bytes.slice(index, index + length);
            index += length;

            if (type === 0 && length === 32) eventId = bytesToHex(value);
            else if (type === 1) relays.push(decoder.decode(new Uint8Array(value)));
            else if (type === 2 && length === 32) author = bytesToHex(value);
            else if (type === 3) kind = value.reduce((total, byte) => (total << 8) | byte, 0);
        }

        if (!eventId) throw new Error("nevent carries no event id");
        return { eventId, relays, author, kind, note1String: reference, format: "nevent" };
    } catch (error) {
        console.error("Failed to decode nevent1:", error);
        return null;
    }
}

/**
 * Decode an `naddr1` reference (NIP-19): the coordinate of an *addressable* event - its kind, its author and its
 * `d` identifier. This is what clients hand you for a calendar event, because kinds 31922/31923 are addressable:
 * the same event can be replaced by its author, so an id is not the right handle for it.
 */
function decodeNaddr(input) {
    const match = String(input).match(/nostr:naddr1\w+/) || String(input).match(/\bnaddr1\w+/);
    if (!match) return null;

    const reference = match[0];
    try {
        const decoded = bech32.decode(reference.replace(/^nostr:/, ""), 1000);
        if (!decoded || typeof decoded !== "object" || !decoded.words) throw new Error(String(decoded));
        const bytes = bech32.fromWords(decoded.words);
        const decoder = new TextDecoder();

        let identifier = null;
        let author = null;
        let kind = null;
        const relays = [];

        // NIP-19 naddr is TLV: type 0 = the `d` identifier, 1 = relay url, 2 = 32-byte author, 3 = kind
        let index = 0;
        while (index + 1 < bytes.length) {
            const type = bytes[index++];
            const length = bytes[index++];
            if (length === undefined || index + length > bytes.length) break;
            const value = bytes.slice(index, index + length);
            index += length;

            if (type === 0) identifier = decoder.decode(new Uint8Array(value));
            else if (type === 1) relays.push(decoder.decode(new Uint8Array(value)));
            else if (type === 2 && length === 32) author = bytesToHex(value);
            else if (type === 3) kind = value.reduce((total, byte) => (total << 8) | byte, 0);
        }

        if (identifier === null || !author || !kind) throw new Error("naddr needs an identifier, an author and a kind");
        return { identifier, author, kind, relays, note1String: reference, format: "naddr" };
    } catch (error) {
        console.error("Failed to decode naddr1:", error);
        return null;
    }
}

/** NIP-52: a date-based calendar event, or a time-based one. */
const CALENDAR_KINDS = [31922, 31923];
function isCalendarKind(kind) {
    return CALENDAR_KINDS.includes(Number(kind));
}

/** Text from a tag, escaped: the values come off a relay and end up inside this page's markup. */
function eventTag(event, name) {
    const tag = (event.tags || []).find(entry => entry[0] === name);
    return tag && typeof tag[1] === "string" ? tag[1] : null;
}

function escapeEventText(text) {
    return String(text == null ? "" : text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

/**
 * A human date for a calendar event. NIP-52 splits the two kinds: 31922 carries `YYYY-MM-DD` strings and its `end`
 * is *exclusive*, while 31923 carries unix seconds and may name a timezone. Both are shown in the reader's locale.
 */
function formatCalendarWhen(event) {
    const start = eventTag(event, "start");
    const end = eventTag(event, "end");
    if (!start) return null;

    if (Number(event.kind) === 31922) {
        const parse = iso => {
            const match = String(iso).match(/^(\d{4})-(\d{2})-(\d{2})$/);
            return match ? Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3])) : null;
        };
        const startAt = parse(start);
        if (startAt === null) return String(start);
        let endAt = end ? parse(end) : null;
        if (endAt !== null) endAt -= 86400000;   // NIP-52's `end` is the day after the last day
        const day = new Date(startAt);
        const full = {day: "numeric", month: "short", year: "numeric", timeZone: "UTC"};
        const short = {day: "numeric", month: "short", timeZone: "UTC"};
        const startText = day.toLocaleDateString(undefined, full);
        if (endAt === null || endAt <= startAt) return startText;
        const last = new Date(endAt);
        const sameYear = last.getUTCFullYear() === day.getUTCFullYear();
        return startText + " – " + last.toLocaleDateString(undefined, sameYear ? short : full);
    }

    const startAt = new Date(Number(start) * 1000);
    if (Number.isNaN(startAt.getTime())) return String(start);
    const endRaw = end ? new Date(Number(end) * 1000) : null;
    const endAt = endRaw && !Number.isNaN(endRaw.getTime()) ? endRaw : null;
    const tzid = eventTag(event, "start_tzid");
    const timeZone = tzid && /^[A-Za-z]+\/[A-Za-z_+\-0-9]+$/.test(tzid) ? tzid : undefined;

    const dayStyle = {weekday: "short", day: "numeric", month: "short", year: "numeric", timeZone};
    const timeStyle = {hour: "2-digit", minute: "2-digit", timeZone, timeZoneName: "short"};
    let text = startAt.toLocaleString(undefined, dayStyle) + " · " + startAt.toLocaleString(undefined, timeStyle);
    if (endAt && endAt > startAt) {
        const sameDay = startAt.toLocaleDateString("en-CA", {timeZone}) === endAt.toLocaleDateString("en-CA", {timeZone});
        text += " – " + (sameDay ? "" : endAt.toLocaleString(undefined, dayStyle) + " · ") +
            endAt.toLocaleString(undefined, timeStyle);
    }
    return text;
}

// Convert bytes to hex string
function bytesToHex(bytes) {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

// Cache to store fetched events
const fetchedEvents = new Set();

/**
 * Fetch an addressable event by its coordinate (kind + author + `d`) and hand it to the same renderer the id-based
 * path uses. An addressable event has no stable id to ask for — its author may replace it — so this is the only
 * correct way to resolve an `naddr1`.
 */
async function fetchCalendarEvent(decoded, relays, reference) {
    const cacheKey = `${decoded.kind}:${decoded.author}:${decoded.identifier}`;
    if (fetchedEvents.has(cacheKey)) return;

    const relayList = relays && relays.length ? relays : defaultRelays;
    const paragraph = document.querySelector('#customParagraph');
    let fetched = false;

    if (paragraph && paragraph.innerHTML.includes(reference)) {
        paragraph.innerHTML = paragraph.innerHTML.replace(
            reference,
            '<span style="color: #bbc013;">[Calendar event catching...]</span>'
        );
    }

    const timeoutId = setTimeout(() => {
        if (fetched) return;
        const placeholder = paragraph && paragraph.querySelector('span[style="color: #bbc013;"]');
        if (placeholder) {
            placeholder.outerHTML = '<span style="color: #FF6347;">[Calendar event not found]</span>';
            applyModalListenersToMedia(paragraph);
        }
    }, 20000);

    for (const relay of relayList) {
        if (fetched) break;
        try {
            const socket = new WebSocket(relay);
            socket.onopen = () => {
                socket.send(JSON.stringify(["REQ", "calendarReference", {
                    kinds: [Number(decoded.kind)],
                    authors: [decoded.author],
                    "#d": [decoded.identifier],
                }]));
            };
            socket.onmessage = (message) => {
                const data = JSON.parse(message.data);
                if (data[0] !== "EVENT" || !data[2]) return;
                if (fetched) return;
                clearTimeout(timeoutId);
                fetched = true;
                fetchedEvents.add(cacheKey);
                renderNostrReference(data[2], reference);
                socket.close();
            };
            socket.onclose = () => {
                if (!fetched && relay === relayList[relayList.length - 1] && relayList !== defaultRelays) {
                    fetchCalendarEvent(decoded, defaultRelays, reference);
                }
            };
            socket.onerror = (error) => console.error(`Error connecting to ${relay}:`, error);
        } catch (error) {
            console.error(`Failed to fetch the calendar event from ${relay}:`, error);
        }
    }
}

/** One way in: whatever came back, a calendar event is drawn as a card and anything else as the note box. */
function renderNostrReference(event, reference) {
    if (isCalendarKind(event.kind)) displayCalendarEvent(event, reference);
    else displayNote1Event(event, reference);
}

/** NIP-52 calendar event as a card: title, when, where, what, and a way out to njump. */
function displayCalendarEvent(event, reference) {
    const paragraph = document.querySelector('#customParagraph');
    if (!paragraph) return;

    if (!paragraph.getAttribute('data-full-content')) {
        paragraph.setAttribute('data-full-content', paragraph.innerHTML);
    }

    const title = eventTag(event, "title") || eventTag(event, "name") || "Untitled event";
    const when = formatCalendarWhen(event);
    const where = eventTag(event, "location");
    const summary = eventTag(event, "summary") || (event.content || "").trim();
    const image = eventTag(event, "image");
    const isDateBased = Number(event.kind) === 31922;

    // The sentinels matter: truncateParagraph slices the page's markup by length, and without a marker it will
    // happily cut through the middle of a card, leaving its title and date but not its place or summary.
    const card = `<!--ref:start--><div class="cal-event">
            <div class="cal-event__label">${isDateBased ? "Calendar · date" : "Calendar · time"}</div>
            <div class="cal-event__title">${escapeEventText(title)}</div>
            ${when ? `<div class="cal-event__when">${escapeEventText(when)}</div>` : ""}
            ${where ? `<div class="cal-event__where">${escapeEventText(where)}</div>` : ""}
            ${summary ? `<div class="cal-event__summary">${escapeEventText(summary).slice(0, 600)}</div>` : ""}
            ${image && /^https?:\/\//i.test(image) ? `<img class="cal-event__image" src="${escapeEventText(image)}" alt="">` : ""}
            <a class="cal-event__link" href="https://njump.me/${escapeEventText(String(reference).replace(/^nostr:/, ""))}" target="_blank" rel="noopener">open in njump &#8669;</a>
        </div><!--ref:end-->
    `;

    const fullContent = paragraph.getAttribute('data-full-content');
    const updated = fullContent.replace(reference, card);
    paragraph.setAttribute('data-full-content', updated);
    if (paragraph.getAttribute('data-expanded') === "true") paragraph.innerHTML = updated;
    else truncateParagraph(paragraph);
    applyModalListenersToMedia(paragraph);
}
// Fetch the note1 event from relays (stop after first success)
// If event not found, retry with default relays
async function fetchNote1Event(eventId, relays, note1String) {

    // If the event is already fetched, skip fetching it again
    if (fetchedEvents.has(eventId)) {
        console.log(`Event ${eventId} already fetched. Skipping...`);
        return;
    }

    const relayList = relays && relays.length ? relays : defaultRelays;
    console.log("Using relays:", relayList);

    let eventFetched = false;
    const paragraph = document.querySelector('#customParagraph');

    // Replace note1 string with colored placeholder
    if (paragraph.innerHTML.includes(note1String)) {
        paragraph.innerHTML = paragraph.innerHTML.replace(
            note1String,
            '<span style="color: #bbc013;">[Event catching...]</span>'
        );
    }

// Timeout to replace placeholder with "Event not found"
const timeoutId = setTimeout(() => {
    if (!eventFetched) {
        console.warn(`Event ${eventId} not found. Replacing placeholder.`);

        // Locate the specific placeholder and replace it without re-rendering the entire paragraph
        const placeholder = paragraph.querySelector('span[style="color: #bbc013;"]');
        if (placeholder) {
            placeholder.outerHTML = '<span style="color: #FF6347;">[Event not found]</span>';
            console.log("Replaced placeholder with 'Event not found'.");
        }

        // Reapply modal listeners
        applyModalListenersToMedia(paragraph);
    }
}, 20000); // 20-second timeout for fallback


    for (const relay of relayList) {
        if (eventFetched) break;

        try {
            const socket = new WebSocket(relay);

            socket.onopen = () => {
                const sub = ["REQ", "subscriptionId", { ids: [eventId] }];
                // console.log(`Requesting event ${eventId} from ${relay}`);
                socket.send(JSON.stringify(sub));
            };

            socket.onmessage = (message) => {
                const data = JSON.parse(message.data);
                if (data[0] === "EVENT") {
                    if (!eventFetched) {
                        clearTimeout(timeoutId);  // Clear timeout when event is fetched
                        // a kind 31922/31923 event is a calendar entry, not a note: same fetch, different card
                        renderNostrReference(data[2], note1String);
                        fetchedEvents.add(eventId);  // Cache the fetched event ID
                        eventFetched = true;
                    }
                    socket.close();  // Close after first successful fetch
                }
            };

            socket.onclose = () => {
                console.log(`Relay ${relay} closed connection.`);
                if (!eventFetched && relay === relayList[relayList.length - 1]) {
                    console.warn("No event found on provided relays. Retrying with default relays...");
                    if (relayList !== defaultRelays) {
                        fetchNote1Event(eventId, defaultRelays, note1String);
                    }
                }
            };

            socket.onerror = (error) => {
                console.error(`Error connecting to ${relay}:`, error);
            };

        } catch (error) {
            console.error(`Failed to fetch event from ${relay}:`, error);
        }
    }
}


// Toggle Like State and Send Reaction to Relays
async function toggleLike(eventId, pubkey) {
    const likeIcon = document.getElementById(`like-icon-${eventId}`);
    const privateKey = localStorage.getItem("nostr_pk");
    const publicKey = localStorage.getItem("nostr_pub");

    if (!privateKey || !publicKey) {
        alert("Private/Public key not found. Please log in.");
        return;
    }

    // Update local liked_events
    updateLocalLikedEvents(eventId);

    // Sync to HEX{pubkey}.json
    syncLikedEventsToHex(publicKey);

    // Construct Reaction Event (NIP-25)
    const reactionEvent = {
        pubkey: publicKey,
        created_at: Math.floor(Date.now() / 1000),
        kind: 7,
        tags: [
            ["e", eventId],  // Event ID being liked
            ["p", pubkey]   // Pubkey of the event creator
            // ["emoji", "+"]
        ],
        content: "+"
    };

    // Sign and Send the Event
    const signedEvent = await signEvent(reactionEvent, privateKey);
    propagateReaction(signedEvent);

    // Disable the like button after liking
    likeIcon.src = "img/othrIcon/like_1.png";
    likeIcon.dataset.liked = "true";
    likeIcon.style.pointerEvents = "none";  // Disable clicks
    likeIcon.title = "Already Liked";
}

// Update liked events in localStorage (persistent)
function updateLocalLikedEvents(eventId) {
    let likedEvents = JSON.parse(localStorage.getItem("liked_events")) || [];

    // Avoid duplicates
    if (!likedEvents.includes(eventId)) {
        likedEvents.push(eventId);
    }

    // Store updated liked events
    localStorage.setItem("liked_events", JSON.stringify(likedEvents));
}

// Sync liked events to HEX{pubkey}.json
function syncLikedEventsToHex(publicKey) {
    const fileName = `HEX${publicKey}.json`;
    let storedData = localStorage.getItem(fileName);
    let data;

    if (storedData) {
        data = JSON.parse(storedData);
    } else {
        data = { events: [], pk: publicKey };
    }

    // Retrieve liked events from localStorage
    const likedEvents = JSON.parse(localStorage.getItem("liked_events")) || [];
    // console.log("Liked Events in localStorage:", likedEvents);

    // Merge liked events back into HEX file
    data.likedEvents = likedEvents;

    // Save updated HEX file
    localStorage.setItem(fileName, JSON.stringify(data));
}

// Store liked events in the user's HEX{pubkey}.json
function storeLikedEvent(eventId, publicKey, eventCreatorPubkey) {
    const fileName = `HEX${publicKey}.json`;
    let storedData = localStorage.getItem(fileName);
    let data;

    // Initialize or parse existing data
    if (storedData) {
        data = JSON.parse(storedData);
    } else {
        data = { events: [], likedEvents: [], pk: publicKey };
    }

    // Ensure likedEvents array exists
    if (!data.likedEvents) {
        data.likedEvents = [];
    }

    // Avoid duplicate likes
    if (!data.likedEvents.includes(eventId)) {
        data.likedEvents.push(eventId);
    }

    // Save back to localStorage
    localStorage.setItem(fileName, JSON.stringify(data));
}

// On Post (kind 1) - Preserve liked events
function saveEvent(event) {
    const publicKey = localStorage.getItem("nostr_pub");
    const fileName = `HEX${publicKey}.json`;
    let storedData = localStorage.getItem(fileName);
    let data;

    if (storedData) {
        data = JSON.parse(storedData);
    } else {
        data = { events: [], pk: publicKey };
    }

    // Add the new event to the events array
    data.events.push(event);

    // Preserve liked events by syncing them back
    data.likedEvents = data.likedEvents || [];
    const localLikedEvents = JSON.parse(localStorage.getItem("liked_events")) || [];
    data.likedEvents = [...new Set([...data.likedEvents, ...localLikedEvents])];

    // Save updated HEX file
    localStorage.setItem(fileName, JSON.stringify(data));
}

// Send the Signed Reaction Event to Relays (Prioritize URL relays)
function propagateReaction(event) {
    const params = new URLSearchParams(window.location.search);
    const relayParam = params.getAll('r');

    // Use relays from URL if they exist; fallback to default relays
    const relayList = relayParam.length ? relayParam : defaultRelays;

    let relaysTried = 0;
    let relaysFailed = 0;

    for (const relay of relayList) {
        try {
            const socket = new WebSocket(relay);

            socket.onopen = () => {
                socket.send(JSON.stringify(["EVENT", event]));
                console.log(`Reaction propagated to ${relay}`);
            };

            socket.onmessage = (message) => {
                const data = JSON.parse(message.data);
                // console.log(`Relay response from ${relay}:`, data);

                // Check if relay returned 'OK' and propagate to others if not
                if (data[0] === 'OK' && data[2] === true) {
                    socket.close();
                } else {
                    relaysFailed++;
                }
            };

            socket.onerror = (error) => {
                console.error(`Failed to send reaction to ${relay}:`, error);
                relaysFailed++;
            };

            socket.onclose = () => {
                relaysTried++;
                console.log(`Connection to ${relay} closed.`);
                // Retry default relays if all custom relays fail
                if (relaysTried === relayList.length && relaysFailed > 0) {
                    console.warn("All custom relays failed. Retrying with default relays...");
                    fallbackToDefaultRelaysForReactions(event);
                }
            };

        } catch (error) {
            console.error(`WebSocket Error for ${relay}:`, error);
            relaysFailed++;
        }
    }
}

// Fallback to Default Relays if Custom Relays Fail
function fallbackToDefaultRelaysForReactions(event) {
    defaultRelays.forEach(relay => {
        try {
            const socket = new WebSocket(relay);
            socket.onopen = () => {
                socket.send(JSON.stringify(["EVENT", event]));
                console.log(`Reaction propagated to default relay: ${relay}`);
                socket.close();
            };
            socket.onerror = (error) => {
                console.error(`Default relay failed: ${relay}`, error);
            };
        } catch (error) {
            console.error(`Error sending to default relay ${relay}:`, error);
        }
    });
}

// Sign the Reaction Event
async function signEvent(event, privateKey) {
    const encoder = new TextEncoder();
    const message = JSON.stringify([
        0, event.pubkey, event.created_at, event.kind, event.tags, event.content
    ]);
    const hash = await crypto.subtle.digest("SHA-256", encoder.encode(message));
    const id = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join("");

    event.id = id;
    event.sig = await schnorr.sign(id, privateKey);
    return event;
}

// Helper function to generate a random color
function generateRandomColor() {
    const letters = '0123456789ABCDEF';
    let color = '#';
    for (let i = 0; i < 6; i++) {
        color += letters[Math.floor(Math.random() * 16)];
    }
    return color;
}

// Display the fetched note1 event in the paragraph section
function displayNote1Event(eventData, note1String) {
    const paragraph = document.querySelector('#customParagraph');

    // Preserve the original full content if not already saved
    if (!paragraph.getAttribute('data-full-content')) {
        paragraph.setAttribute('data-full-content', paragraph.innerHTML);
    }

    // Generate a random color for a pencil icon
    const randomColor = generateRandomColor();

    // Get the current full content
    const fullContent = paragraph.getAttribute('data-full-content');

    // Replace the matching placeholder or `note1String` with the styled noteBox
    const noteBox = `
        <div class="note-box">
            <a href="https://njump.me/${eventData.id}" target="_blank" title="Show event in external source njump.me">
                <span style="font-size:30px; cursor: pointer; color: ${randomColor};">&#8669;</span>
            </a>
            ${replaceMediaLinks(eventData.content)}
            <div class="note-details" id="note-details-${eventData.id}">
                <strong>Event JSON:</strong>
                <pre>${JSON.stringify(eventData, null, 2)}</pre>
            </div>
            <div class="note-header">
                <img src="img/othrIcon/like_0.png" id="like-icon-${eventData.id}" 
                     class="icon like-icon" alt="Like" title="Like Event" 
                     onclick="toggleLike('${eventData.id}', '${eventData.pubkey}')"
                     data-liked="false">
                <img src="img/othrIcon/details.png" class="icon details-icon" 
                     alt="Details" title="View Details" 
                     onclick="toggleDetails('${eventData.id}')">
            </div>
        </div>
    `;

    // Replace placeholder or `note1String` with the styled noteBox
    const updatedContent = fullContent.replace(note1String, noteBox);
    paragraph.setAttribute('data-full-content', updatedContent);

    // Update the paragraph based on its current state (truncated or full)
    if (paragraph.getAttribute('data-expanded') === "true") {
        paragraph.innerHTML = updatedContent; // Expand to full content
    } else {
        truncateParagraph(paragraph); // Keep it truncated
    }

    // Apply modal listeners to media in the updated content
    applyModalListenersToMedia(paragraph);

    // Apply likes after rendering the noteBox
    markLikedEvents();
}

    function markLikedEvents() {
        const publicKey = localStorage.getItem("nostr_pub");
        const fileName = `HEX${publicKey}.json`;
        const storedData = localStorage.getItem(fileName);

        if (storedData) {
            const data = JSON.parse(storedData);
            if (data.likedEvents) {
                // Delay to ensure DOM is fully rendered
                setTimeout(() => {
                    data.likedEvents.forEach(eventId => {
                        const likeIcon = document.getElementById(`like-icon-${eventId}`);
                        if (likeIcon) {
                            likeIcon.src = "img/othrIcon/like_1.png";
                            likeIcon.dataset.liked = "true";
                            likeIcon.style.pointerEvents = "none";  // Disable clicks
                            likeIcon.title = "Already Liked";
                        }
                    });
                }, 500); // 500ms delay
            }
        }
    }

// Toggle function for showing/hiding JSON details
function toggleDetails(eventId) {
    // console.log(`Toggling details for eventId: ${eventId}`);

    // Close any currently open details first
    const openDetails = document.querySelectorAll('.note-details.visible');
    openDetails.forEach(detail => {
        if (detail.id !== `note-details-${eventId}`) {
            // console.log(`Closing other open details: ${detail.id}`);
            detail.classList.remove('visible');
        }
    });

    // Toggle the current detail's visibility
    const details = document.getElementById(`note-details-${eventId}`);
    if (details) {
        details.classList.toggle('visible');
        // console.log(`Details for eventId ${eventId} are now ${details.classList.contains('visible') ? 'open' : 'closed'}`);
    } else {
        console.warn(`Details for eventId ${eventId} not found!`);
    }
}

// Close note details when clicking outside
document.addEventListener('click', (event) => {
    // console.log("Click detected outside, checking for open details...");

    const noteBoxes = document.querySelectorAll('.note-box');

    let clickedInsideAnyNoteBox = false;

    noteBoxes.forEach(box => {
        const details = box.querySelector('.note-details');

        if (details && details.classList.contains('visible')) {
            console.log(`Checking visibility for details: ${details.id}`);
        }

        // Check if the click is inside any visible note-box
        if (box.contains(event.target)) {
            // console.log(`Click detected inside note-box: ${box}`);
            clickedInsideAnyNoteBox = true;
        }
    });

    // Close all details if the click was outside any note-box
    if (!clickedInsideAnyNoteBox) {
        // console.log("Click outside all note-boxes. Closing all visible details.");
        const visibleDetails = document.querySelectorAll('.note-details.visible');
        visibleDetails.forEach(details => {
            // console.log(`Closing visible details: ${details.id}`);
            details.classList.remove('visible');
        });
    }
});

// Prevent event propagation when clicking on details icons
document.querySelectorAll('.details-icon').forEach(icon => {
    icon.addEventListener('click', (e) => {
        e.stopPropagation();
        // console.log("Click event on details-icon stopped from propagating.");
    });
});


// On page load, extract and handle note1 from the p= attribute and if there's no note1 string display p= as is
// window.onload = () => {
//     const params = new URLSearchParams(window.location.search);
//     const pValue = params.get('p') || '';
//     const relayParam = params.getAll('r');
    
//     const customParagraph = document.getElementById('customParagraph');

//     if (!pValue.match(/(?:nostr:)?note1/)) {  // Match either "note1" or "nostr:note1"
//         // No note1 string, simply display the paragraph as normal
//         customParagraph.setAttribute('data-full-content', pValue || "");
//         truncateParagraph(customParagraph); // Ensure truncation applies
//     } else {
//         const note1Matches = pValue.match(/(?:nostr:)?note1\w+/g) || [];  // Match both formats
//         if (note1Matches.length > 0) {
//             note1Matches.forEach(note1String => {
//                 const { eventId } = decodeNote1(note1String) || {};
//                 if (eventId) {
//                     fetchNote1Event(eventId, relayParam, note1String);
//                 }
//             });
//         } else {
//             customParagraph.textContent = "No valid note1 found in URL.";
//             truncateParagraph(customParagraph); // Ensure truncation applies
//         }
//     }
// };

window.onload = () => {
    const params = new URLSearchParams(window.location.search);
    let pValue = params.get('p') || '';
    // a poll declared in the content is a card under the page, never text in it: the same split the page itself
    // does, taken from the same function, or this second write puts the token back
    if (typeof window.snoflContentWithoutPolls === 'function') {
        pValue = window.snoflContentWithoutPolls(pValue).text;
    }
    const relayParam = params.getAll('r');
    
    const customParagraph = document.getElementById('customParagraph');

    // Check for "nostr:note1" strings explicitly
    const note1Matches = pValue.match(/nostr:note1\w+/g) || [];
    const plainNote1Matches = pValue.match(/\bnote1\w+\b(?!:)/g) || []; // Match "note1" without "nostr:"

    if (plainNote1Matches.length > 0) {
        // Handle plain "note1" strings as normal text
        plainNote1Matches.forEach(note1String => {
            pValue = pValue.replace(note1String, `<span>${note1String}</span>`); // Display as raw text
        });
    }

    if (note1Matches.length > 0) {
        // Handle "nostr:note1" strings for fetching
        note1Matches.forEach(note1String => {
            const { eventId } = decodeNote1(note1String) || {};
            if (eventId) {
                fetchNote1Event(eventId, relayParam, note1String);
            }
        });
    } else if (plainNote1Matches.length === 0) {
        // No "nostr:note1" or "note1" strings
        customParagraph.setAttribute('data-full-content', pValue || "");
        truncateParagraph(customParagraph);
    }
};


// On page load, mark liked events
document.addEventListener("DOMContentLoaded", () => {
    const publicKey = localStorage.getItem("nostr_pub");
    const fileName = `HEX${publicKey}.json`;
    const storedData = localStorage.getItem(fileName);

    if (storedData) {
        const data = JSON.parse(storedData);
        if (data.likedEvents) {
            setTimeout(() => {
                data.likedEvents.forEach(eventId => {
                    const likeIcon = document.getElementById(`like-icon-${eventId}`);
                    if (likeIcon) {
                        likeIcon.src = "img/othrIcon/like_1.png";
                        likeIcon.dataset.liked = "true";
                    }
                });
            }, 1500);  // 1500ms delay);
        }
    }
});