// src's own layer, kept out of the search script: the identity badge and the votes on search results.
//
// Both borrow the custom pages' model rather than inventing one. The identity is the same browser key the
// custom pages use (`nostr_pk` / `nostr_pub` / `nostr_name` in localStorage), so a vote cast here is signed by
// the same npub as a note posted there, and clicking the badge runs the same consent-then-generate flow.
// Votes are NIP-25 kind 7 with `+` / `-`, tagged with the note's id and author, published to the relays the
// search itself uses.
(function () {
    "use strict";

    const CONSENT_COOKIE = "snofl_random_Nostr_ID_cookie_consent";
    // The custom pages lock a fresh ID for 24 hours before it may be replaced (`checkAccountAge()` in index.html
    // reads the same `acc_created_at`), so a random ID cannot be farmed. src honours the same clock.
    const COOLDOWN_SECONDS = 86400;
    const HEX = "0123456789abcdef";

    const $ = (id) => document.getElementById(id);

    function bytesToHex(bytes) {
        let out = "";
        for (const byte of bytes) out += HEX[byte >> 4] + HEX[byte & 15];
        return out;
    }

    function hexToBytes(hex) {
        const out = new Uint8Array(hex.length / 2);
        for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
        return out;
    }

    async function sha256Hex(text) {
        const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
        return bytesToHex(new Uint8Array(digest));
    }

    // ---------------------------------------------------------------- identity

    function readIdentity() {
        const pub = localStorage.getItem("nostr_pub");
        const pk = localStorage.getItem("nostr_pk");
        return pub && pk ? { pub, pk, name: localStorage.getItem("nostr_name") || "" } : null;
    }

    function setCookie(name, value, days) {
        document.cookie = `${name}=${value}; max-age=${days * 24 * 60 * 60}; path=/; samesite=lax`;
    }

    function hasCookie(name) {
        return document.cookie.split("; ").some((part) => part.startsWith(name + "="));
    }

    /** When this browser's current ID was minted, in seconds; null when the record predates the cooldown. */
    function createdAt() {
        const stored = parseInt(localStorage.getItem("acc_created_at"), 10);
        return Number.isFinite(stored) && stored > 0 ? stored : null;
    }

    /**
     * How far the ID is through its lock. An ID with no recorded birthday (minted before `acc_created_at`
     * existed) is treated as fully aged rather than blocked, so nobody is trapped by a stale record.
     */
    function cooldown() {
        const created = createdAt();
        if (created === null) return { known: false, created: null, age: null, remaining: 0, progress: 1 };
        const age = Math.max(0, Math.floor(Date.now() / 1000) - created);
        return {
            known: true,
            created,
            age,
            remaining: Math.max(0, COOLDOWN_SECONDS - age),
            progress: Math.min(1, age / COOLDOWN_SECONDS),
        };
    }

    function humanDuration(seconds) {
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const parts = [];
        if (days) parts.push(`${days} day${days === 1 ? "" : "s"}`);
        if (hours) parts.push(`${hours} hour${hours === 1 ? "" : "s"}`);
        if (!days && minutes) parts.push(`${minutes} minute${minutes === 1 ? "" : "s"}`);
        return parts.length ? parts.join(" ") : "less than a minute";
    }

    function clockOf(seconds) {
        return new Date(seconds * 1000).toLocaleString(undefined, {
            day: "numeric", month: "short", hour: "2-digit", minute: "2-digit",
        });
    }

    function fallbackName() {
        const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        return Array.from({ length: 10 }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
    }

    async function generateName() {
        try {
            const [adjectives, nouns] = await Promise.all([
                fetch("adjectives.json").then((r) => r.json()),
                fetch("nouns.json").then((r) => r.json()),
            ]);
            const number = String(Math.floor(Math.random() * 21) + 1).padStart(2, "0");
            return `${adjectives[Math.floor(Math.random() * adjectives.length)]}_` +
                `${nouns[Math.floor(Math.random() * nouns.length)]}_${number}`;
        } catch {
            return fallbackName();
        }
    }

    /**
     * The library the custom pages use puts everything on one object: `schnorr` for signing and `utils` for the
     * key generation (`utils.randomPrivateKey()`, since this version of schnorr has no generatePrivateKey).
     * It is loaded from a CDN, so wait for it rather than assuming it has arrived.
     */
    async function signer() {
        for (let attempt = 0; attempt < 40; attempt++) {
            const bundle = window.nobleSecp256k1;
            if (bundle && bundle.schnorr && bundle.utils) return bundle;
            await new Promise((resolve) => setTimeout(resolve, 250));
        }
        throw new Error("the signer (noble-secp256k1) did not load");
    }

    async function createIdentity() {
        const { schnorr, utils } = await signer();
        const pk = bytesToHex(utils.randomPrivateKey());
        // schnorr.getPublicKey returns the 32-byte x-only key, which is what a Nostr pubkey is
        const pub = schnorr.getPublicKey(pk);
        const name = await generateName();
        localStorage.setItem("nostr_pk", pk);
        localStorage.setItem("nostr_pub", pub);
        localStorage.setItem("nostr_name", name);
        // the birthday the 24-hour lock is measured from, shared with the custom pages
        localStorage.setItem("acc_created_at", String(Math.floor(Date.now() / 1000)));
        localStorage.setItem("src_signed_actions", "0");
        return { pk, pub, name };
    }

    function avatarUrl(pub) {
        const stored = localStorage.getItem("avatar_url");
        if (stored) return stored;
        return `https://api.dicebear.com/11.x/croodles/svg?seed=${encodeURIComponent(pub || "placeholder")}`;
    }

    function paintIdentity() {
        const badge = $("srcId");
        const image = $("srcAvatar");
        const label = $("srcName");
        if (!badge) return;
        const identity = readIdentity();
        if (!identity) {
            badge.classList.add("is-empty");
            image.removeAttribute("src");
            label.textContent = "get ID";
            badge.title = "No ID on this device yet · click to create one";
            return;
        }
        badge.classList.remove("is-empty");
        image.src = avatarUrl(identity.pub);
        label.textContent = identity.name || fallbackName();

        // the 2px ring around the avatar: how far this ID is through its lock, red -> orange -> yellow -> green
        const state = cooldown();
        const ring = $("srcAvatarRing");
        if (ring) {
            // the arc never drops below a visible sliver, so a brand-new ID is a red ring, not a bare avatar
            ring.style.setProperty("--ring-progress", `${Math.max(4, Math.round(state.progress * 100))}%`);
            ring.style.setProperty("--ring-hue", `${Math.round(state.progress * 120)}`);
            ring.classList.toggle("is-locked", state.remaining > 0);
        }

        const age = state.age === null ? "age unknown" : `age ${humanDuration(state.age)}`;
        const lock = state.remaining > 0 ? `new ID in ${humanDuration(state.remaining)}` : "new ID available";
        badge.title = `${identity.name || "unnamed"} · ${age} · ${lock} · click to change it`;
    }

    /** The custom pages' flow: ask once, then generate. */
    async function createWithConsent() {
        if (!hasCookie(CONSENT_COOKIE)) {
            const agreed = confirm(
                "This page needs a random Nostr ID so your votes carry a name.\n\n" +
                "Do you agree to create a random Nostr ID and store its private key in this device's local " +
                "storage? A consent cookie is saved too.\n\nWithout it you can read and search, but not vote."
            );
            if (!agreed) return null;
            setCookie(CONSENT_COOKIE, "true", 365);
        }
        const identity = await createIdentity();
        paintIdentity();
        return identity;
    }

    async function ensureIdentity() {
        return readIdentity() || (await createWithConsent());
    }

    async function onBadgeClick() {
        const identity = readIdentity();
        if (!identity) {
            await createWithConsent();
            return;
        }

        const state = cooldown();
        const name = identity.name || "(unnamed)";
        const ageLine = state.age === null
            ? "This ID has no recorded birthday, so the 24-hour wait does not apply."
            : `This ID is ${humanDuration(state.age)} old (created ${clockOf(state.created)}).`;

        // still inside the 24-hour lock: say how old it is and exactly when a new one is allowed
        if (state.remaining > 0) {
            alert(
                `Your ID is ${name}.\n\n${ageLine}\n\n` +
                `A new ID is allowed in ${humanDuration(state.remaining)}, at ` +
                `${clockOf(state.created + COOLDOWN_SECONDS)}.\n\n` +
                "The 24-hour wait keeps random IDs from being farmed for votes; the custom pages enforce the " +
                "same rule on this browser."
            );
            return;
        }

        // the custom pages want one posted note before a replacement; here any signed action counts
        const actions = parseInt(localStorage.getItem("src_signed_actions") || "0", 10);
        if (!(actions > 0)) {
            alert(
                `Your ID is ${name}.\n\n${ageLine}\n\n` +
                "Vote on at least one note before replacing it — that is this page's version of the custom " +
                'pages\' "post something first" rule, and it keeps ID minting tied to real use.'
            );
            return;
        }

        const agreed = confirm(
            `Your ID is ${name}.\n\n${ageLine}\n\n` +
            "You can create a new ID now. Replace it? The old key is dropped from this browser and anything " +
            "already signed stays signed by it."
        );
        if (!agreed) return;
        await createIdentity();
        paintIdentity();
        if (window.snoflSrcVotes) window.snoflSrcVotes.refresh(true);
    }

    // ---------------------------------------------------------------- relays

    /** The relays the search is already talking to, so a vote lands where the notes were found. */
    function relays() {
        const params = new URLSearchParams(location.search);
        let list = [];
        if (params.has("r")) {
            list = decodeURIComponent(params.get("r")).split(",").filter(Boolean);
        }
        const pool = (typeof NIP50Relays !== "undefined" && Array.isArray(NIP50Relays)) ? NIP50Relays : [];
        return [...new Set([...list, ...pool])];
    }

    /** Publish one signed event and resolve with how many relays accepted it. */
    function publish(event, timeout = 6000) {
        const targets = relays();
        return new Promise((resolve) => {
            let accepted = 0;
            let settled = 0;
            if (!targets.length) return resolve(0);
            const finish = () => {
                settled += 1;
                if (settled === targets.length) resolve(accepted);
            };
            const timer = setTimeout(() => resolve(accepted), timeout);
            targets.forEach((relay) => {
                let socket;
                try {
                    socket = new WebSocket(relay);
                } catch {
                    finish();
                    return;
                }
                const close = () => {
                    try { socket.close(); } catch { /* already gone */ }
                    finish();
                };
                socket.onopen = () => {
                    try {
                        socket.send(JSON.stringify(["EVENT", event]));
                    } catch {
                        close();
                    }
                };
                socket.onmessage = (message) => {
                    try {
                        const data = JSON.parse(message.data);
                        if (data[0] === "OK" && data[1] === event.id) {
                            if (data[2] === true) accepted += 1;
                            close();
                        }
                    } catch { /* not ours */ }
                };
                socket.onerror = close;
                socket.onclose = close;
            });
            setTimeout(() => {
                clearTimeout(timer);
                resolve(accepted);
            }, timeout);
        });
    }

    async function sign(identity, kind, content, tags) {
        const event = {
            kind,
            pubkey: identity.pub,
            created_at: Math.floor(Date.now() / 1000),
            tags,
            content,
        };
        event.id = await sha256Hex(JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]));
        const { schnorr } = await signer();
        const signature = await schnorr.sign(event.id, identity.pk);
        event.sig = typeof signature === "string" ? signature : bytesToHex(signature);
        return event;
    }

    // ---------------------------------------------------------------- votes

    const counts = new Map();   // note id -> {up: Set(pubkey), down: Set(pubkey)}
    let inFlight = false;

    function countFor(noteId) {
        return counts.get(noteId) || { up: new Set(), down: new Set() };
    }

    function paintVotes() {
        const me = readIdentity();
        document.querySelectorAll(".note-votes").forEach((block) => {
            const noteId = block.dataset.noteId;
            const entry = countFor(noteId);
            const number = block.querySelector(".vote-count");
            const up = block.querySelector(".vote-up");
            const down = block.querySelector(".vote-down");
            const upCount = entry.up.size;
            const downCount = entry.down.size;
            if (number) number.textContent = upCount + downCount === 0 ? "·" : `${upCount}/${downCount}`;
            if (up) up.classList.toggle("is-mine", !!(me && entry.up.has(me.pub)));
            if (down) down.classList.toggle("is-mine", !!(me && entry.down.has(me.pub)));
        });
    }

    /** Ask the relays for the kind-7 reactions of the notes on screen. */
    async function refresh(force) {
        if (inFlight && !force) return;
        const ids = [...document.querySelectorAll(".note-votes")].map((block) => block.dataset.noteId).filter(Boolean);
        if (!ids.length) return;
        inFlight = true;
        const targets = relays();
        const seen = new Set();
        await Promise.all(targets.map((relay) => new Promise((resolve) => {
            let socket;
            try {
                socket = new WebSocket(relay);
            } catch {
                return resolve();
            }
            const done = () => {
                try { socket.close(); } catch { /* gone */ }
                resolve();
            };
            const timer = setTimeout(done, 7000);
            socket.onopen = () => {
                try {
                    socket.send(JSON.stringify(["REQ", "src-votes", { kinds: [7], "#e": ids, limit: 1000 }]));
                } catch { done(); }
            };
            socket.onmessage = (message) => {
                try {
                    const data = JSON.parse(message.data);
                    if (data[0] === "EOSE") {
                        clearTimeout(timer);
                        return done();
                    }
                    if (data[0] !== "EVENT") return;
                    const reaction = data[2];
                    if (!reaction || reaction.kind !== 7 || seen.has(reaction.id)) return;
                    seen.add(reaction.id);
                    const target = (reaction.tags || []).find((tag) => tag[0] === "e");
                    if (!target || !ids.includes(target[1])) return;
                    const entry = counts.get(target[1]) || { up: new Set(), down: new Set() };
                    if (reaction.content === "-") entry.down.add(reaction.pubkey);
                    else entry.up.add(reaction.pubkey);   // "+", an emoji or empty all mean up (NIP-25)
                    counts.set(target[1], entry);
                } catch { /* not ours */ }
            };
            socket.onerror = done;
            socket.onclose = () => {
                clearTimeout(timer);
                resolve();
            };
        })));
        inFlight = false;
        paintVotes();
    }

    async function vote(block, direction, button) {
        const noteId = block.dataset.noteId;
        const notePubkey = block.dataset.notePubkey;
        if (!noteId) return;
        button.disabled = true;
        try {
            const identity = await ensureIdentity();
            if (!identity) return;
            const entry = counts.get(noteId) || { up: new Set(), down: new Set() };
            const same = direction === "+" ? entry.up : entry.down;
            const other = direction === "+" ? entry.down : entry.up;

            // pressing the arrow you already pressed withdraws the vote, as on any other client
            const withdrawing = same.has(identity.pub);
            const tags = [["e", noteId]];
            if (notePubkey) tags.push(["p", notePubkey]);

            if (withdrawing) {
                same.delete(identity.pub);
            } else {
                same.add(identity.pub);
                other.delete(identity.pub);
            }
            paintVotes();

            if (withdrawing) {
                // NIP-09: ask the relays to drop the reaction this key published
                const previous = await findOwnReaction(noteId, identity.pub);
                if (previous) {
                    const deletion = await sign(identity, 5, "", [["e", previous], ["k", "7"]]);
                    await publish(deletion);
                }
                return;
            }

            const event = await sign(identity, 7, direction, tags);
            const accepted = await publish(event);
            if (accepted > 0) {
                const counted = parseInt(localStorage.getItem("src_signed_actions") || "0", 10);
                localStorage.setItem("src_signed_actions", String(counted + 1));
            }
        } finally {
            button.disabled = false;
            refresh(true);
        }
    }

    /** The id of this key's existing reaction to a note, so a vote can be withdrawn. */
    async function findOwnReaction(noteId, pubkey) {
        const targets = relays();
        return new Promise((resolve) => {
            let found = null;
            let settled = 0;
            if (!targets.length) return resolve(null);
            const finish = () => {
                settled += 1;
                if (settled === targets.length) resolve(found);
            };
            targets.forEach((relay) => {
                let socket;
                try {
                    socket = new WebSocket(relay);
                } catch {
                    return finish();
                }
                const timer = setTimeout(finish, 5000);
                const done = () => {
                    clearTimeout(timer);
                    try { socket.close(); } catch { /* gone */ }
                    finish();
                };
                socket.onopen = () => {
                    try {
                        socket.send(JSON.stringify(["REQ", "src-own", { kinds: [7], "#e": [noteId], authors: [pubkey], limit: 5 }]));
                    } catch { done(); }
                };
                socket.onmessage = (message) => {
                    try {
                        const data = JSON.parse(message.data);
                        if (data[0] === "EVENT" && data[2] && data[2].pubkey === pubkey) found = data[2].id;
                        if (data[0] === "EOSE") done();
                    } catch { /* not ours */ }
                };
                socket.onerror = done;
                socket.onclose = done;
            });
        });
    }

    // ---------------------------------------------------------------- wiring

    function wire() {
        const badge = $("srcId");
        if (badge) {
            badge.addEventListener("click", onBadgeClick);
            badge.addEventListener("keydown", (event) => {
                if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    onBadgeClick();
                }
            });
        }

        // one listener for every arrow, on the container, because the list is re-rendered constantly
        const list = $("notes");
        if (list) {
            list.addEventListener("click", (event) => {
                const button = event.target.closest(".vote");
                if (!button) return;
                const block = button.closest(".note-votes");
                if (!block) return;
                event.preventDefault();
                vote(block, button.dataset.dir, button);
            });
        }

        paintIdentity();
        // the ring advances on its own: no reload needed to watch an ID unlock
        setInterval(paintIdentity, 60000);
    }

    // `vote` and `ensureIdentity` are exposed for the same reason `refresh` is: so a probe can drive the real
    // flow instead of re-implementing it.
    window.snoflSrcVotes = { refresh, vote, ensureIdentity };

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", wire);
    } else {
        wire();
    }
})();
