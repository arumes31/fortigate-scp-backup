        document.addEventListener('DOMContentLoaded', function() {
            const logoText = document.getElementById('logo-text');
            const originalText = 'FortiSafe';
            const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#@$%';

            // Matrix rain animation for logo, starting with "FGT"
            function matrixRain() {
                let displayText = 'FGT'; // Start with "FGT"
                const speed = 100; // ms per character drop
                let charIndex = 3; // Start after "FGT" (index 0, 1, 2)

                function dropNextChar() {
                    if (charIndex < originalText.length) {
                        displayText += characters.charAt(Math.floor(Math.random() * characters.length));
                        logoText.textContent = displayText;
                        charIndex++;
                        setTimeout(dropNextChar, speed);
                    } else {
                        // After all characters drop, stabilize to original text
                        setTimeout(() => {
                            logoText.textContent = originalText;
                            setTimeout(matrixRain, 4000); // Restart after 4s
                        }, 1000); // Hold random chars for 1s before stabilizing
                    }
                }
                dropNextChar();
            }

            // Start the matrix rain animation
            matrixRain();

            // On submit, show a waiting hint and disable the button: a RADIUS/MFA
            // sign-in can take up to 60s and may need approval on the user's phone.
            var loginForm = document.getElementById('login-form');
            var loginSubmit = document.getElementById('login-submit');
            var loginWait = document.getElementById('login-wait');
            if (loginForm) {
                loginForm.addEventListener('submit', function () {
                    if (loginWait) { loginWait.classList.add('show'); }
                    if (loginSubmit) {
                        loginSubmit.disabled = true;
                        loginSubmit.value = loginForm.dataset.signingIn || 'Signing in…';
                    }
                });
            }
        });

    // WebGL shader backdrop (self-contained, same-origin, CSP-safe). Crimson
    // matches the app's --danger (#ff2b2b). Falls back silently to the CSS
    // gradient when WebGL is unavailable; honours prefers-reduced-motion by
    // rendering a single static frame instead of animating.
    (function () {
        const canvas = document.getElementById('loginShader');
        if (!canvas || !canvas.getContext) return;
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (!gl) return;

        function syncSize() {
            const w = canvas.clientWidth || 1280;
            const h = canvas.clientHeight || 720;
            if (canvas.width !== w || canvas.height !== h) {
                canvas.width = w;
                canvas.height = h;
            }
        }
        if (typeof ResizeObserver !== 'undefined') new ResizeObserver(syncSize).observe(canvas);
        syncSize();

        const vs = `attribute vec2 a_position;
varying vec2 v_texCoord;
void main() {
  v_texCoord = a_position * 0.5 + 0.5;
  gl_Position = vec4(a_position, 0.0, 1.0);
}`;
        // Default: vertical firewall beams with thermal haze + floor reflection.
        const fsBeams = `precision highp float;
uniform float u_time;
uniform vec2 u_resolution;
varying vec2 v_texCoord;
float hash(vec2 p) { return fract(sin(dot(p, vec2(12.9898, 78.233))) * 43758.5453); }
void main() {
    vec2 uv = (v_texCoord - 0.5) * u_resolution.xy / min(u_resolution.x, u_resolution.y);
    float t = u_time * 0.5;
    vec3 crimson = vec3(1.0, 0.168, 0.168);
    vec3 bg = vec3(0.04, 0.01, 0.01);
    float beam = 0.0;
    for (float i = 0.0; i < 10.0; i++) {
        float x = (hash(vec2(i, 123.0)) - 0.5) * 2.5;
        float speed = 0.2 + hash(vec2(i, 456.0)) * 0.8;
        float wave = sin(uv.y * 3.0 + t * speed + i) * 0.1;
        float d = abs(uv.x - (x + wave));
        beam += (0.005 / d) * (0.5 + 0.5 * sin(t + i));
    }
    float haze = sin(uv.y * 10.0 - t * 2.0) * 0.5 + 0.5;
    vec3 color = mix(bg, crimson * 0.4, beam);
    color += crimson * beam * 0.2 * haze;
    float reflection = smoothstep(-0.5, -1.5, uv.y) * 0.3;
    color += crimson * reflection * beam;
    gl_FragColor = vec4(color, 1.0);
}`;
        // Rare variant (~10% of loads): flowing interference field.
        const fsFlow = `precision highp float;
uniform float u_time;
uniform vec2 u_resolution;
varying vec2 v_texCoord;
void main() {
    vec2 uv = (v_texCoord - 0.5) * u_resolution.xy / min(u_resolution.x, u_resolution.y);
    float t = u_time * 0.15;
    vec3 crimson = vec3(1.0, 0.168, 0.168);
    float flow = 0.0;
    vec2 p = uv * 2.0;
    for (float i = 1.0; i < 6.0; i++) {
        p += vec2(sin(p.y + t + i), cos(p.x + t - i));
        flow += abs(sin(length(p) - t)) * (1.0 / i);
    }
    vec3 color = mix(vec3(0.04, 0.01, 0.01), crimson * 0.5, pow(flow, 2.0) * 0.3);
    float grain = fract(sin(dot(v_texCoord, vec2(12.9898, 78.233))) * 43758.5453);
    color += crimson * grain * 0.03;
    gl_FragColor = vec4(color, 1.0);
}`;
        const fs = Math.random() < 0.1 ? fsFlow : fsBeams;

        function cs(type, src) {
            const sh = gl.createShader(type);
            gl.shaderSource(sh, src);
            gl.compileShader(sh);
            return sh;
        }
        const prog = gl.createProgram();
        gl.attachShader(prog, cs(gl.VERTEX_SHADER, vs));
        gl.attachShader(prog, cs(gl.FRAGMENT_SHADER, fs));
        gl.linkProgram(prog);
        if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) return; // keep the CSS fallback
        gl.useProgram(prog);
        const buf = gl.createBuffer();
        gl.bindBuffer(gl.ARRAY_BUFFER, buf);
        gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
        const pos = gl.getAttribLocation(prog, 'a_position');
        gl.enableVertexAttribArray(pos);
        gl.vertexAttribPointer(pos, 2, gl.FLOAT, false, 0, 0);
        const uTime = gl.getUniformLocation(prog, 'u_time');
        const uRes = gl.getUniformLocation(prog, 'u_resolution');

        function frame(t) {
            gl.viewport(0, 0, canvas.width, canvas.height);
            if (uTime) gl.uniform1f(uTime, t * 0.001);
            if (uRes) gl.uniform2f(uRes, canvas.width, canvas.height);
            gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
        }
        const still = typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;
        if (still) { frame(12000); return; } // one static frame, no loop
        (function loop(t) { frame(t); requestAnimationFrame(loop); })(0);
    })();
