document.body.addEventListener("deleteDuplicateRow", function (evt) {
  let el = document.getElementById(evt.detail.hash);
  if (el) {
    el.classList.add("fade-out");

    setTimeout(function () {
      el.remove();
    }, 1000);
  }
});

document.body.addEventListener("htmx:responseError", function (event) {
  const serverError = document.getElementById("server-error");
  const errorMessageElement = document.getElementById("error-message");

  // Display error container
  serverError.style.display = "block";
  setTimeout(() => serverError.classList.add("active"), 0); // Delay to trigger transition

  // Set error message
  errorMessageElement.textContent =
    event.detail.xhr.responseText || "An unknown error occurred";
});

document.body.addEventListener("htmx:afterSwap", function (event) {
  // Hide error container on successful response
  const serverError = document.getElementById("server-error");
  serverError.style.display = "none";
  serverError.classList.remove("active");
});
