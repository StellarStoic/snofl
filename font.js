let isFontListLoaded = false;

// Dynamically load fontList.js
function loadFontList(callback) {
    // index.html already loads fontList.js with a tag, so loading it again here threw
    // "Identifier 'fontList' has already been declared" and left the console red on every visit.
    if (typeof window.fontList !== 'undefined') {
        isFontListLoaded = true;
        callback();
        return;
    }
    if (isFontListLoaded) {
        console.log('fontList.js already loaded. Skipping...');
        callback();
        return;
    }

    const script = document.createElement('script');
    script.src = 'fontList.js';
    script.onload = () => {
        isFontListLoaded = true;
        callback();
    };
    script.onerror = () => {
        console.error('Failed to load fontList.js. Retrying in 10 seconds...');
        setTimeout(() => loadFontList(callback), 10000); // Retry after 10 seconds
    };
    document.head.appendChild(script);
}

// Apply font from storage or URL parameters
function applyFont(retryCount = 0) {
    const MAX_RETRIES = 3; // Set a maximum number of retries
    if (retryCount >= MAX_RETRIES) {
        console.error('Max retries reached. Falling back to sans-serif.');
        document.documentElement.style.setProperty('--main-font', 'sans-serif');
        return;
    }
    const params = new URLSearchParams(window.location.search);
    const urlFontIndex = params.get('f');  // Font from URL
    const storedFontIndex = localStorage.getItem('selectedFontIndex') || sessionStorage.getItem('selectedFontIndex');
    
    // Priority: Storage > URL > Default to 1 (Inconsolata)
    const fontIndex = storedFontIndex || urlFontIndex || '1';

    // Check if fontList is loaded
    if (typeof fontList === 'undefined') {
        console.error('Font list not loaded. Retrying in 10 seconds...');
        setTimeout(() => applyFont(retryCount + 1), 10000); // Retry after 10 seconds
        return;
    }

    // Apply font or fallback to sans-serif
    if (fontList[fontIndex]) {
        const fontImport = fontList[fontIndex];

        if (fontImport.includes(':')) {
            // Load Bunny font dynamically
            const link = document.createElement('link');
            link.rel = 'stylesheet';
            link.href = `https://fonts.bunny.net/css?family=${fontImport}`;
            link.onerror = () => {
                console.error(`Failed to load Bunny font: ${fontImport}. Retrying in 10 seconds...`);
                setTimeout(() => applyFont(retryCount + 1), 10000); // Retry after 10 seconds
            };
            document.head.appendChild(link);

            // Extract font name and replace dashes with spaces
            const fontName = fontImport.split(':')[0].replace(/-/g, ' '); 
            document.documentElement.style.setProperty('--main-font', `'${fontName}', sans-serif`);
            console.log(`Applied Bunny font: ${fontName} (Index: ${fontIndex})`);
        } else {
            // Apply system fonts directly (like Arial, sans-serif)
            document.documentElement.style.setProperty('--main-font', fontImport);
            console.log(`Applied system font: ${fontImport} (Index: ${fontIndex})`);
        }

        // Save the applied font index to storage if it was from the URL
        if (urlFontIndex) {
            localStorage.setItem('selectedFontIndex', urlFontIndex);  // Persist user choice
            console.log(`Saved font index to storage: ${urlFontIndex}`);
        }
    } else {
        // Fallback to sans-serif if font index not found
        console.warn(`Font index (${fontIndex}) not found. Applying sans-serif.`);
        document.documentElement.style.setProperty('--main-font', 'sans-serif');
    }
}

// Load font list first, then apply font
loadFontList(() => {
    console.log('Font list loaded. Applying font...');
    applyFont();
});
