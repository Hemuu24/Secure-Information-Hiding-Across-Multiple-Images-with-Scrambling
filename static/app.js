/*
Simple "decrypted text" style heading animation inspired by ReactBits.
It progressively resolves random characters into the final text.
*/

(function () {
    const GLYPHS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";

    function randomGlyph() {
        return GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
    }

    function animateElement(el) {
        const target = el.getAttribute("data-text") || el.textContent || "";
        let frame = 0;
        const totalFrames = 54;
        const intervalMs = 65;

        const timer = setInterval(function () {
            const progress = frame / totalFrames;
            let output = "";

            for (let i = 0; i < target.length; i += 1) {
                const revealThreshold = i / Math.max(target.length, 1);
                if (progress >= revealThreshold) {
                    output += target[i];
                } else {
                    output += target[i] === " " ? " " : randomGlyph();
                }
            }

            el.textContent = output;
            frame += 1;
            if (frame > totalFrames) {
                clearInterval(timer);
                el.textContent = target;
            }
        }, intervalMs);
    }

    function initPixelBlastBackground() {
        const canvas = document.createElement("canvas");
        canvas.className = "pixel-blast-bg";
        document.body.prepend(canvas);

        const ctx = canvas.getContext("2d");
        if (!ctx) return;

        let width = 1;
        let height = 1;
        const dpr = Math.min(window.devicePixelRatio || 1, 2);
        const ripples = [];
        const maxRipples = 6;

        function resize() {
            width = window.innerWidth;
            height = window.innerHeight;
            canvas.width = Math.floor(width * dpr);
            canvas.height = Math.floor(height * dpr);
            canvas.style.width = width + "px";
            canvas.style.height = height + "px";
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        }

        function addRipple(x, y) {
            ripples.unshift({ x, y, t: 0, strength: 1 });
            if (ripples.length > maxRipples) ripples.pop();
        }

        function drawPixel(x, y, size, color) {
            ctx.fillStyle = color;
            ctx.fillRect(x, y, size, size);
        }

        function render(timeMs) {
            const t = timeMs * 0.00045;
            ctx.clearRect(0, 0, width, height);
            ctx.fillStyle = "#050505";
            ctx.fillRect(0, 0, width, height);

            // Pixel field similar to "blast" style (black/white only).
            const cell = 18;
            for (let y = 0; y < height; y += cell) {
                for (let x = 0; x < width; x += cell) {
                    const nx = x / width;
                    const ny = y / height;

                    // Base evolving field.
                    let v = Math.sin((nx * 9.0 + t * 0.2) * Math.PI);
                    v += Math.cos((ny * 10.0 - t * 0.18) * Math.PI);
                    v += Math.sin((nx + ny + t * 0.12) * 20.0);
                    v = v / 3.0;

                    // Ripple influence from pointer clicks/moves.
                    for (let i = ripples.length - 1; i >= 0; i -= 1) {
                        const r = ripples[i];
                        const dx = x - r.x;
                        const dy = y - r.y;
                        const dist = Math.sqrt(dx * dx + dy * dy);
                        const waveFront = r.t * 120.0;
                        const band = Math.exp(-Math.pow((dist - waveFront) / 34.0, 2.0));
                        const atten = Math.exp(-r.t * 1.6) * r.strength;
                        v += band * atten * 0.35;
                    }

                    // Dither threshold for pixelated black/white look.
                    const threshold = ((x / cell + y / cell) % 2) * 0.04 - 0.02;
                    const on = v + threshold > 0.2;
                    drawPixel(x, y, cell - 2, on ? "#2e2e2e" : "#111111");
                }
            }

            // Update ripple clocks and remove old ones.
            for (let i = ripples.length - 1; i >= 0; i -= 1) {
                ripples[i].t += 0.016;
                if (ripples[i].t > 1.6) ripples.splice(i, 1);
            }

            requestAnimationFrame(render);
        }

        window.addEventListener("resize", resize);
        window.addEventListener(
            "pointerdown",
            function (e) {
                addRipple(e.clientX, e.clientY);
            },
            { passive: true }
        );

        resize();
        requestAnimationFrame(render);
    }

    window.addEventListener("DOMContentLoaded", function () {
        const elements = document.querySelectorAll(".decrypted-text");
        elements.forEach(animateElement);
        initPixelBlastBackground();
    });
})();
