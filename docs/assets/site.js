// The iotap website. Everything on the page works without this file; it adds the replay of the
// example trace, the tabs, the copy buttons and the link between a caption and its line.
(() => {
  "use strict";

  const root = document.documentElement;
  root.classList.add("js");
  const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  // The example trace types its command, then prints one line at a time, paced like the trace.
  const trace = document.getElementById("trace");
  if (trace) {
    const typed = trace.querySelector("[data-typed]");
    const lines = [...trace.querySelectorAll(".ln")];
    const captions = [...document.querySelectorAll(".story li")];
    const text = typed ? typed.dataset.typed : "";
    let run = 0;

    // Timers of a tab that is not showing run a second apart or slower, so the trace is played
    // only while the tab is showing, and is complete when it is not.
    const finish = () => {
      typed.textContent = text;
      lines.forEach((line) => line.classList.remove("pending"));
    };

    const play = async () => {
      const mine = ++run;
      lines.forEach((line) => line.classList.add("pending"));
      typed.textContent = "";
      for (const ch of text) {
        if (mine !== run) return;
        if (document.hidden) return finish();
        typed.textContent += ch;
        await sleep(42);
      }
      await sleep(280);
      for (const line of lines) {
        if (mine !== run) return;
        if (document.hidden) return finish();
        line.classList.remove("pending");
        await sleep(Number(line.dataset.pause || 180));
      }
    };

    const show = (id, on) => {
      trace.querySelector(`[data-call="${id}"]`)?.classList.toggle("on", on);
      document.querySelector(`.story [data-call="${id}"]`)?.classList.toggle("on", on);
    };

    for (const caption of captions) {
      const id = caption.dataset.call;
      caption.addEventListener("mouseenter", () => show(id, true));
      caption.addEventListener("mouseleave", () => show(id, false));
      caption.addEventListener("focus", () => show(id, true));
      caption.addEventListener("blur", () => show(id, false));
    }
    for (const line of lines.filter((l) => l.dataset.call)) {
      const id = line.dataset.call;
      line.addEventListener("mouseenter", () => show(id, true));
      line.addEventListener("mouseleave", () => show(id, false));
    }

    document.getElementById("replay")?.addEventListener("click", () => {
      if (!reduceMotion) play();
    });
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) {
        run += 1;
        finish();
      }
    });
    if (!reduceMotion) {
      if (document.hidden) {
        document.addEventListener("visibilitychange", () => !document.hidden && play(), { once: true });
      } else {
        play();
      }
    }
  }

  // Tabs, as the WAI-ARIA authoring practices have them: arrow keys move, one tab is in the tab order.
  for (const list of document.querySelectorAll('[role="tablist"]')) {
    const tabs = [...list.querySelectorAll('[role="tab"]')];
    const select = (tab, focus) => {
      for (const t of tabs) {
        const on = t === tab;
        t.setAttribute("aria-selected", String(on));
        t.tabIndex = on ? 0 : -1;
        document.getElementById(t.getAttribute("aria-controls")).hidden = !on;
      }
      if (focus) tab.focus();
    };
    list.addEventListener("click", (event) => {
      const tab = event.target.closest('[role="tab"]');
      if (tab) select(tab, false);
    });
    list.addEventListener("keydown", (event) => {
      const at = tabs.indexOf(document.activeElement);
      if (at < 0) return;
      const to = {
        ArrowRight: (at + 1) % tabs.length,
        ArrowLeft: (at - 1 + tabs.length) % tabs.length,
        Home: 0,
        End: tabs.length - 1,
      }[event.key];
      if (to !== undefined) {
        event.preventDefault();
        select(tabs[to], true);
      }
    });
    select(tabs[0], false);
    for (const panel of document.querySelectorAll("[data-later]")) panel.removeAttribute("data-later");
  }

  // Copy buttons copy the commands of the block, without its comments, which a shell may not take.
  for (const button of document.querySelectorAll("[data-copy]")) {
    const label = button.textContent;
    const status = document.getElementById("status");
    button.addEventListener("click", async () => {
      const block = document.getElementById(button.dataset.copy).cloneNode(true);
      block.querySelectorAll(".c").forEach((comment) => comment.remove());
      const text = block.textContent
        .split("\n")
        .map((line) => line.trimEnd())
        .join("\n")
        .trim();
      try {
        await navigator.clipboard.writeText(text);
      } catch {
        const area = Object.assign(document.createElement("textarea"), { value: text });
        document.body.append(area);
        area.select();
        document.execCommand("copy");
        area.remove();
      }
      button.textContent = "Copied";
      if (status) status.textContent = "Copied to the clipboard";
      await sleep(1800);
      button.textContent = label;
      if (status) status.textContent = "";
    });
  }
})();
