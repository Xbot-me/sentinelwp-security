/**
 * Official Stripe Elements Mock Integration (Legitimate Client Code)
 */
jQuery(function($) {
    var stripe = Stripe('pk_test_TYoo6PFDCEDemoKey');
    var elements = stripe.elements();
    var cardElement = elements.create('card', {
        style: {
            base: {
                fontSize: '16px',
                color: '#32325d',
            }
        }
    });
    cardElement.mount('#stripe-card-element');
    cardElement.on('change', function(event) {
        var displayError = document.getElementById('card-errors');
        if (event.error) {
            displayError.textContent = event.error.message;
        } else {
            displayError.textContent = '';
        }
    });
});
