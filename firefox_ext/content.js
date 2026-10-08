// Return storage data back to background requested
(() => {
  const locStorage = {};
  const sessStorage = {};

  try {
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      locStorage[key] = localStorage.getItem(key);
    }
  } catch (e) {
    locStorage["__error"] = e.toString();
  }

  try {
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      sessStorage[key] = sessionStorage.getItem(key);
    }
  } catch (e) {
    sessStorage["__error"] = e.toString();
  }

  return {
    localStorage: locStorage,
    sessionStorage: sessStorage,
    pageTitle: document.title
  };
})();