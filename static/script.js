// CSRF token storage
let csrfToken = null;

// Fetch CSRF token from the server
async function fetchCsrfToken() {
  try {
    const response = await fetch('/api/csrf-token');
    if (!response.ok) {
      console.error('Failed to fetch CSRF token');
      return null;
    }
    const data = await response.json();
    csrfToken = data.csrf_token;
    console.log('CSRF token fetched successfully');
    return csrfToken;
  } catch (error) {
    console.error('Error fetching CSRF token:', error);
    return null;
  }
}

// Get CSRF token - returns stored token or null
function getCsrfToken() {
  return csrfToken;
}

// Handle product-specific links, payment popup, and redirects
document.addEventListener('DOMContentLoaded', function() {
  console.log('DOM fully loaded and parsed');
  
  // Fetch CSRF token as soon as page loads
  fetchCsrfToken();
  
  // Get elements
  const buyButton = document.querySelector('.buy-button');
  const paymentPopup = document.getElementById('paymentPopup');
  const closePopupBtn = document.getElementById('closePopup');
  const paymentMethodButtons = document.querySelectorAll('.payment-method-button');
  
  // Email Collection Modal elements
  const emailModal = document.getElementById('emailCollectionModal');
  const closeEmailModalBtn = document.getElementById('closeEmailModal');
  const continueToPaymentBtn = document.getElementById('continueToPayment');
  const customerEmailInput = document.getElementById('customerEmail');
  const emailError = document.getElementById('emailError');
  
  // Promo code elements
  const promoCodeInput = document.getElementById('promoCode');
  const applyPromoButton = document.getElementById('applyPromoCode');
  const promoCodeMessage = document.getElementById('promoCodeMessage');
  const promoDiscount = document.getElementById('promoDiscount');
  
  // Store validated promo code info in window scope so it's accessible to other functions
  window.validatedPromoCode = null;
  
  // Flag to prevent duplicate validation requests
  let isValidating = false;
  
  // Quantity controls
  const quantityInput = document.getElementById('quantity');
  const decreaseBtn = document.querySelector('.quantity-btn.decrease');
  const increaseBtn = document.querySelector('.quantity-btn.increase');
  
  // Set up quantity controls if they exist
  if (quantityInput && decreaseBtn && increaseBtn) {
    // Decrease quantity
    decreaseBtn.addEventListener('click', function() {
      const currentValue = parseInt(quantityInput.value);
      if (currentValue > 1) {
        quantityInput.value = currentValue - 1;
      }
    });
    
    // Increase quantity
    increaseBtn.addEventListener('click', function() {
      const currentValue = parseInt(quantityInput.value);
      if (currentValue < 25) {
        quantityInput.value = currentValue + 1;
      }
    });
    
    // Ensure valid input
    quantityInput.addEventListener('change', function() {
      const value = parseInt(this.value);
      if (isNaN(value) || value < 1) {
        this.value = 1;
      } else if (value > 25) {
        this.value = 25;
      }
    });
  }
  
  // Store current product ID in window scope
  window.currentProductId = '';
  
  // Open payment popup when buy button is clicked
  if (buyButton) {
    buyButton.addEventListener('click', function(e) {
      e.preventDefault();
      console.log('Buy button clicked');
      
      // Get the product ID from the URL
      const productPath = window.location.pathname;
      console.log('Current path:', productPath);
      
      // Try various patterns to extract the product ID
      let productMatch = productPath.match(/product-([^.]+)\.html/);
      
      if (productMatch && productMatch[1]) {
        window.currentProductId = productMatch[1];
        console.log('Extracted product ID from pattern 1:', window.currentProductId);
      } else {
        // Try another pattern
        productMatch = productPath.match(/products\/product-([^.]+)\.html/);
        if (productMatch && productMatch[1]) {
          window.currentProductId = productMatch[1];
          console.log('Extracted product ID from pattern 2:', window.currentProductId);
        } else {
          // Try without the .html
          productMatch = productPath.match(/product-([^/.]+)/);
          if (productMatch && productMatch[1]) {
            window.currentProductId = productMatch[1];
            console.log('Extracted product ID without .html:', window.currentProductId);
          } else {
            // One more attempt - get the file name
            const pathParts = productPath.split('/');
            const fileName = pathParts[pathParts.length - 1];
            console.log('File name:', fileName);
            
            if (fileName.startsWith('product-') && fileName.endsWith('.html')) {
              window.currentProductId = fileName.replace('product-', '').replace('.html', '');
              console.log('Extracted product ID from filename:', window.currentProductId);
            } else if (fileName.startsWith('product-')) {
              window.currentProductId = fileName.replace('product-', '');
              console.log('Extracted product ID from filename without .html:', window.currentProductId);
            } else {
              console.error('Could not determine product ID from URL.');
              return;
            }
          }
        }
      }
      
      // Show the payment popup
      if (paymentPopup) {
        paymentPopup.classList.add('active');
        
        // Reset promo code when opening popup
        resetPromoCode();
        
        // Prevent scrolling on the body
        document.body.style.overflow = 'hidden';
      } else {
        console.error('Payment popup element not found');
      }
    });
  }
  
  // Close popup when close button is clicked
  if (closePopupBtn) {
    closePopupBtn.addEventListener('click', function() {
      paymentPopup.classList.remove('active');
      document.body.style.overflow = '';
    });
  }
  
  // Close popup when clicking outside the popup content
  if (paymentPopup) {
    paymentPopup.addEventListener('click', function(event) {
      if (event.target === paymentPopup) {
        paymentPopup.classList.remove('active');
        document.body.style.overflow = '';
      }
    });
  }
  
  // Close email modal when close button is clicked
  if (closeEmailModalBtn) {
    closeEmailModalBtn.addEventListener('click', function() {
      emailModal.classList.remove('active');
      document.body.style.overflow = '';
      
      // Reopen the payment popup
      if (paymentPopup) {
        paymentPopup.classList.add('active');
      }
    });
  }
  
  // Close email modal when clicking outside
  if (emailModal) {
    emailModal.addEventListener('click', function(event) {
      if (event.target === emailModal) {
        emailModal.classList.remove('active');
        document.body.style.overflow = '';
        
        // Reopen the payment popup
        if (paymentPopup) {
          paymentPopup.classList.add('active');
        }
      }
    });
  }
  
  // Email validation on input
  if (customerEmailInput) {
    customerEmailInput.addEventListener('input', function() {
      if (emailError) {
        emailError.style.display = 'none';
      }
    });
    
    // Handle enter key
    customerEmailInput.addEventListener('keypress', function(e) {
      if (e.key === 'Enter' && continueToPaymentBtn) {
        e.preventDefault();
        continueToPaymentBtn.click();
      }
    });
  }
  
  // Apply promo code button click handler - with duplicate prevention
  if (applyPromoButton) {
    applyPromoButton.addEventListener('click', function(e) {
      e.preventDefault();
      if (!isValidating) {
        validatePromoCode();
      }
    });
  }
  
  // Handle Enter key in the promo input field - with duplicate prevention
  if (promoCodeInput) {
    promoCodeInput.addEventListener('keypress', function(e) {
      if (e.key === 'Enter') {
        e.preventDefault();
        if (!isValidating) {
          validatePromoCode();
        }
      }
    });
  }
  
  // Function to validate promo code using the API
  async function validatePromoCode() {
    // Prevent duplicate requests
    if (isValidating) return;
    isValidating = true;
    
    const promoCode = promoCodeInput.value.trim();
    console.log('Validating promo code:', promoCode);
    
    // Clear previous messages
    promoCodeMessage.textContent = '';
    promoCodeMessage.className = 'promo-code-message';
    promoDiscount.textContent = '';
    promoDiscount.className = 'promo-discount';
    
    // If empty, just return without message
    if (!promoCode) {
      window.validatedPromoCode = null;
      isValidating = false;
      return;
    }
    
    // Basic validation
    if (promoCode.length < 4 || promoCode.length > 20) {
      showPromoError('Invalid promo code format');
      isValidating = false;
      return;
    }
    
    // Add security measures to prevent exploits
    if (containsSuspiciousPatterns(promoCode)) {
      showPromoError('Invalid characters in promo code');
      isValidating = false;
      return;
    }
    
    // Show loading state
    promoCodeMessage.textContent = 'Validating...';
    applyPromoButton.disabled = true;
    
    // Ensure we have a product ID
    if (!window.currentProductId) {
      window.currentProductId = extractProductId();
    }
    
    // Make sure product ID has proper format
    if (!window.currentProductId.startsWith('product-')) {
      window.currentProductId = 'product-' + window.currentProductId;
    }
    
    console.log('Making validation request for product ID:', window.currentProductId);
    
    // Ensure we have a CSRF token
    if (!csrfToken) {
      try {
        await fetchCsrfToken();
      } catch (error) {
        console.error('Failed to fetch CSRF token:', error);
      }
    }
    
    // Call API to validate promo code
    fetch('/validate-promo', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrfToken
      },
      body: JSON.stringify({ 
        promoCode: promoCode,
        productId: window.currentProductId
      }),
    })
    .then(response => {
      console.log('Validation response status:', response.status);
      
      if (!response.ok) {
        if (response.status === 404) {
          throw new Error('Promo code not found');
        }
        return response.json().then(err => Promise.reject(err.message || 'Server error'));
      }
      return response.json();
    })
    .then(data => {
      console.log('Validation result:', data);
      
      if (data.valid) {
        // Store the validated code data
        window.validatedPromoCode = {
          code: promoCode,
          discountPercentage: data.discountPercentage,
          discountAmount: data.discountAmount,
          type: data.type // 'percentage' or 'fixed'
        };
        
        // Show success message
        promoCodeMessage.textContent = 'Promo code applied successfully!';
        promoCodeMessage.className = 'promo-code-message success';
        
        // Display discount information
        if (data.type === 'percentage') {
          promoDiscount.textContent = `Discount: ${data.discountPercentage}% off`;
        } else {
          promoDiscount.textContent = `Discount: £${(data.discountAmount/100).toFixed(2)} off`;
        }
        promoDiscount.className = 'promo-discount active';
        
        // Disable input field to prevent changes after validation
        promoCodeInput.disabled = true;
        applyPromoButton.textContent = 'Remove';
        
        // Change button function to remove promo code
        applyPromoButton.onclick = removePromoCode;
      } else {
        showPromoError(data.message || 'Invalid promo code');
        window.validatedPromoCode = null;
      }
    })
    .catch(error => {
      console.error('Promo code validation error:', error);
      showPromoError(error.message || 'Error validating promo code');
      window.validatedPromoCode = null;
    })
    .finally(() => {
      applyPromoButton.disabled = false;
      isValidating = false;
    });
  }
  
  function extractProductId() {
    const productPath = window.location.pathname;
    console.log('Extracting product ID from:', productPath);
    
    // Check if it's in the products directory with product-XX format
    const productsDirectoryMatch = productPath.match(/\/products\/product-(\d+)/);
    if (productsDirectoryMatch) {
      return `products/product-${productsDirectoryMatch[1]}`;
    }
    
    // Check for product-XX at the root level
    const rootProductMatch = productPath.match(/\/product-(\d+)/);
    if (rootProductMatch) {
      return `product-${rootProductMatch[1]}`;
    }
    
    // Check for any file in the products directory
    const productsAnyFileMatch = productPath.match(/\/products\/([^\/]+)/);
    if (productsAnyFileMatch) {
      const filename = productsAnyFileMatch[1];
      // Remove .html extension if present
      const cleanFilename = filename.replace(/\.html$/, '');
      return `products/${cleanFilename}`;
    }
    
    // If we have any product-XX pattern anywhere in the path
    const anyProductMatch = productPath.match(/product-(\d+)/);
    if (anyProductMatch) {
      // Check if it's in a directory structure
      if (productPath.includes('/products/')) {
        return `products/product-${anyProductMatch[1]}`;
      }
      return `product-${anyProductMatch[1]}`;
    }
    
    // Check for any filename at the end of the path that might be a product
    const anyFilenameMatch = productPath.match(/\/([^\/]+)$/);
    if (anyFilenameMatch) {
      const filename = anyFilenameMatch[1];
      // Skip obvious non-product files
      if (!['index.html', 'faq.html', 'login.html', 'admin_dashboard.html'].includes(filename)) {
        // Remove .html extension if present
        const cleanFilename = filename.replace(/\.html$/, '');
        return cleanFilename;
      }
    }
    
    // If we can't determine the product ID, log an error
    console.error('Could not extract product ID from path:', productPath);
    
    // Return null instead of a hardcoded fallback
    return null;
  }
  
  // Function to show promo code error
  function showPromoError(message) {
    promoCodeMessage.textContent = message;
    promoCodeMessage.className = 'promo-code-message error';
    window.validatedPromoCode = null;
  }
  
  // Function to show email validation error
  function showEmailError(message) {
    if (emailError) {
      emailError.textContent = message;
      emailError.style.display = 'block';
    }
  }
  
  // Function to validate email format
  function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }
  
  // Function to reset promo code form
  function resetPromoCode() {
    if (promoCodeInput) {
      promoCodeInput.value = '';
      promoCodeInput.disabled = false;
    }
    
    if (promoCodeMessage) {
      promoCodeMessage.textContent = '';
      promoCodeMessage.className = 'promo-code-message';
    }
    
    if (promoDiscount) {
      promoDiscount.textContent = '';
      promoDiscount.className = 'promo-discount';
    }
    
    if (applyPromoButton) {
      applyPromoButton.textContent = 'Apply';
      applyPromoButton.disabled = false;
      
      // Reset event listener
      applyPromoButton.onclick = function(e) {
        e.preventDefault();
        if (!isValidating) {
          validatePromoCode();
        }
      };
    }
    
    window.validatedPromoCode = null;
  }
  
  // Function to remove applied promo code
  function removePromoCode(e) {
    e.preventDefault();
    resetPromoCode();
    promoCodeMessage.textContent = 'Promo code removed';
  }
  
  // Function to check for potentially malicious input
  function containsSuspiciousPatterns(input) {
    // Check for script tags, SQL injection attempts, etc.
    const suspiciousPatterns = [
      /<script/i,
      /javascript:/i,
      /;/,
      /--/,
      /'/,
      /"/,
      /\\/,
      /\//,
      /=/,
      />/,
      /</
    ];
    
    return suspiciousPatterns.some(pattern => pattern.test(input));
  }
  
  // Handle payment method selection with promo code support
  paymentMethodButtons.forEach(button => {
    button.addEventListener('click', async function() {
      const paymentMethod = this.getAttribute('data-payment-method');
      console.log('Payment method selected:', paymentMethod);
      
      // If we don't have a CSRF token yet, try to fetch it
      if (!csrfToken) {
        try {
          await fetchCsrfToken();
        } catch (error) {
          console.error('Failed to fetch CSRF token for payment:', error);
          alert('Error with payment system. Please try again later.');
          return;
        }
      }
      
      // Inside your payment method button event listener
      if (paymentMethod === 'nowpayments') {
        if (window.currentProductId === 'pages' || !window.currentProductId) {
          console.log('Fixing invalid product ID:', window.currentProductId);
          window.currentProductId = 'product-15';
        }
        // Show the email collection modal
        if (emailModal) {
          emailModal.classList.add('active');
          document.body.style.overflow = 'hidden';
          
          // Focus on the email input
          if (customerEmailInput) {
            customerEmailInput.focus();
          }
          
          // Close the payment popup
          if (paymentPopup) {
            paymentPopup.classList.remove('active');
          }
          
          // Store the current payment method
          window.currentPaymentMethod = paymentMethod;
          
          // Directly update the onclick
          if (continueToPaymentBtn) {
            // Clear any previous handlers by setting onclick directly
            continueToPaymentBtn.onclick = async function() {
              const email = customerEmailInput ? customerEmailInput.value.trim() : '';
            
              // Email validation
              if (!email) {
                showEmailError('Please enter your email address');
                return;
              }
            
              if (!isValidEmail(email)) {
                showEmailError('Please enter a valid email address');
                return;
              }
            
              // Show loading state
              this.disabled = true;
              this.textContent = 'Processing...';
            
              // Get quantity
              let quantity = 1;
              if (quantityInput) {
                quantity = parseInt(quantityInput.value);
                if (isNaN(quantity) || quantity < 1) {
                  quantity = 1;
                } else if (quantity > 25) {
                  quantity = 25;
                }
              }
            
              // Select the endpoint based on the payment method
              const endpoint = '/create-nowpayments-order';
              
              // Process the product ID for API
              let apiProductId = window.currentProductId;
              if (apiProductId.includes('/')) {
                apiProductId = apiProductId.split('/').pop();
              }
              
              // Create the request body
              const requestBody = {
                product_id: apiProductId,
                payment_method: window.currentPaymentMethod,
                quantity: quantity,
                customer_email: email
              };
            
              // Add promo code if valid
              if (window.validatedPromoCode) {
                requestBody.promoCode = window.validatedPromoCode.code;
              }
            
              // Make the API request
              fetch(endpoint, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'X-CSRFToken': csrfToken
                },
                body: JSON.stringify(requestBody),
              })
              .then(response => {
                if (!response.ok) {
                  return response.json().then(errorData => {
                    throw new Error(errorData.error || 'Network response was not ok');
                  });
                }
                return response.json();
              })
              .then(data => {
                // Redirect to the payment page
                if (data.url) {
                  window.location.href = data.url;
                } else {
                  throw new Error('No payment URL returned');
                }
              })
              .catch(error => {
                console.error('Error:', error);
                showEmailError('Error: ' + error.message);
                this.disabled = false;
                this.textContent = 'Continue to Payment';
              });
            };
          }
        }
        
        return; // Exit early
      }
      
      // For other payment methods (Stripe, PayPal, etc.)
      // Show loading state
      this.innerHTML = '<span class="payment-method-name">Processing...</span>';
      this.disabled = true;
      
      // Make sure we have a product ID
      if (!window.currentProductId) {
        window.currentProductId = extractProductId();

        if (!window.currentProductId) {
          console.error('Could not determine product ID from URL');
          alert('Error: Could not determine which product you are trying to purchase. Please try again or contact support.');

          // Reset button
          this.innerHTML = `
            <span class="payment-method-name">${paymentMethod.charAt(0).toUpperCase() + paymentMethod.slice(1)}</span>
            <span class="payment-method-arrow">→</span>
          `;
          this.disabled = false;
          return; // Exit early
        }
      }

      // Prepare the product ID for API calls
      let apiProductId = window.currentProductId;

      // For APIs that expect just the filename without directory:
      if (apiProductId.includes('/')) {
        apiProductId = apiProductId.split('/').pop();
      }
      
      // Fallback for emergency use
      if (!window.currentProductId || window.currentProductId === 'pages/product-15.html') {
        console.log('Using hardcoded fallback product ID');
        window.currentProductId = 'product-15';
      }
      
      // Get quantity from input if available
      let quantity = 1;
      if (quantityInput) {
        quantity = parseInt(quantityInput.value);
        if (isNaN(quantity) || quantity < 1) {
          quantity = 1;
        } else if (quantity > 25) {
          quantity = 25;
        }
      }
      console.log('Using quantity:', quantity);
      
      // Get current path for cancel URL
      let currentPath = window.location.pathname;
      let cancelPath = currentPath;
      
      // Make sure cancel path has no trailing slash
      if (cancelPath.endsWith('/')) {
        cancelPath = cancelPath.slice(0, -1);
      }
      
      // Prepare request body
      const requestBody = {
        product_id: apiProductId,
        payment_method: paymentMethod,
        quantity: quantity,
      };
      
      // Add promo code if valid
      if (window.validatedPromoCode) {
        requestBody.promoCode = window.validatedPromoCode.code;
        console.log('Adding promo code to request:', window.validatedPromoCode.code);
      }

      let endpoint = '/create-checkout-session'; // Default (Stripe)
      
      if (paymentMethod === 'paypal') {
        endpoint = '/create-paypal-order';
      } else if (paymentMethod === 'nowpayments') {
        endpoint = '/create-nowpayments-order';
      }
      
      console.log('Making API request to:', endpoint);
      console.log('Request body:', JSON.stringify(requestBody));
      
      // Make the API request to create a checkout session
      fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': csrfToken
        },
        body: JSON.stringify(requestBody),
      })
      .then(response => {
        console.log('Response status:', response.status);
        if (!response.ok) {
          // Try to get the error message from the response
          return response.json().then(errorData => {
            console.error('API error:', errorData);
            throw new Error(errorData.error || 'Network response was not ok');
          });
        }
        return response.json();
      })
      .then(data => {
        console.log('API response:', data);
        
        // Redirect to the checkout URL
        if (data.url) {
          console.log('Redirecting to:', data.url);
          window.location.href = data.url;
        } else {
          throw new Error('No checkout URL returned');
        }
      })
      .catch(error => {
        console.error('Error:', error);
        alert('There was an error processing your payment: ' + error.message);
        
        // Reset button
        this.innerHTML = `
          <span class="payment-method-name">${paymentMethod.charAt(0).toUpperCase() + paymentMethod.slice(1)}</span>
          <span class="payment-method-arrow">→</span>
        `;
        this.disabled = false;
        
        // Close the popup
        if (paymentPopup) {
          paymentPopup.classList.remove('active');
          document.body.style.overflow = '';
        }
      });
    });
  });
});