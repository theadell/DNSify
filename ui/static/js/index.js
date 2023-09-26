document.addEventListener("DOMContentLoaded", function () {
  var form = document.getElementById("record-form");
  var hostnameInput = document.getElementById("hostname");
  var ipInput = document.getElementById("ip");
  var ttlInput = document.getElementById("ttl");
  var submitBtn = document.getElementById("record-submit-btn");

  hostnameInput.isDirty = false;
  ipInput.isDirty = false;
  ttlInput.isDirty = false;

  var hostnameRegex = /^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)$/;
  var ipRegex = /^(?!0)(?!.*\.$)((1?\d?\d|25[0-5]|2[0-4]\d)(\.|$)){4}$/;

  form.addEventListener("submit", function (e) {
    validateForm(e);
  });

  hostnameInput.addEventListener("blur", function (e) {
    validateHostname(e.target);
  });

  ipInput.addEventListener("blur", function (e) {
    validateIp(e.target);
  });

  ttlInput.addEventListener("blur", function (e) {
    validateTtl(e.target);
  });

  hostnameInput.addEventListener("input", function (e) {
    e.target.isDirty = true;

    validateHostname(e.target);
    toggleButtonState();
  });

  ipInput.addEventListener("input", function (e) {
    e.target.isDirty = true;

    validateIp(e.target);
    toggleButtonState();
  });

  ttlInput.addEventListener("input", function (e) {
    e.target.isDirty = true;

    validateTtl(e.target);
    toggleButtonState();
  });

  function toggleButtonState() {
    submitBtn.disabled =
      !validateHostname(hostnameInput) ||
      !validateIp(ipInput) ||
      !validateTtl(ttlInput);
  }

  function validateForm(e) {
    var isValidHostname = validateHostname(hostnameInput);
    var isValidIp = validateIp(ipInput);
    var isValidTtl = validateTtl(ttlInput);

    if (!isValidHostname || !isValidIp || !isValidTtl) e.preventDefault();
  }

  function validateHostname(input) {
    var errorMessage = input.parentNode.querySelector(".error-message");
    if (input.isDirty) {
      var value = input.value.trim();
      if (!hostnameRegex.test(value)) {
        input.classList.add("error");
        errorMessage.style.opacity = "1"; // Show the error message
        return false;
      }
      input.classList.remove("error");
      errorMessage.style.opacity = "0"; // Hide the error message
      return true;
    }
    errorMessage.style.opacity = "0"; // Hide the error message
    return true;
  }

  function validateIp(input) {
    var errorMessage = input.parentNode.querySelector(".error-message");
    if (input.isDirty) {
      var value = input.value.trim();
      if (!ipRegex.test(value) && value != "@") {
        input.classList.add("error");
        errorMessage.style.opacity = "1"; // Show the error message
        return false;
      }
      input.classList.remove("error");
      errorMessage.style.opacity = "0";
      return true;
    }
    errorMessage.style.opacity = "0";
    return true;
  }

  function validateTtl(input) {
    var errorMessage = input.parentNode.querySelector(".error-message");
    if (input.isDirty) {
      var value = parseInt(input.value.trim(), 10);
      if (isNaN(value) || value < 60) {
        input.classList.add("error");
        errorMessage.style.opacity = "1";
        return false;
      }
      input.classList.remove("error");
      errorMessage.style.opacity = "0";
      return true;
    }
    errorMessage.style.opacity = "0";
    return true;
  }

  const fqdnDisplay = document.getElementById("fqdn");

  hostnameInput.addEventListener("input", function () {
    const hostname = hostnameInput.value.trim();
    fqdnDisplay.textContent = hostname ? `${hostname}.rusty-leipzig.com.` : "";
  });

  var tablist = document.querySelector(".tablist");
  tablist.addEventListener("click", function (e) {
    if (e.target.tagName === "A") {
      var currentActive = tablist.querySelector(".is-active");
      if (currentActive) currentActive.classList.remove("is-active");
      e.target.parentNode.classList.add("is-active");
    }
  });
});
document.body.addEventListener("htmx:responseError", function (event) {
  console.log("I have been triggered");
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
