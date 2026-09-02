(() => {
    "use strict";

    const countdown = document.getElementById("ct-next-poll-countdown");
    if (!countdown) return;

    const target = Date.parse(countdown.dataset.nextPoll || "");
    if (!Number.isFinite(target)) {
        countdown.textContent = "Next run is not scheduled";
        return;
    }

    const update = () => {
        const remaining = Math.max(0, Math.ceil((target - Date.now()) / 1000));
        if (remaining === 0) {
            countdown.textContent = "Due now";
            return;
        }
        const hours = Math.floor(remaining / 3600);
        const minutes = Math.floor((remaining % 3600) / 60);
        const seconds = remaining % 60;
        const parts = [];
        if (hours > 0) parts.push(`${hours}h`);
        if (minutes > 0 || hours > 0) parts.push(`${minutes}m`);
        parts.push(`${seconds}s`);
        countdown.textContent = `in ${parts.join(" ")}`;
    };

    update();
    window.setInterval(update, 1000);
})();
