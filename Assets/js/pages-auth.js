"use strict";
const formAuthentication = document.querySelector("#formAuthentication");
document.addEventListener("DOMContentLoaded", function(e) {
    var t;
    formAuthentication && FormValidation.formValidation(formAuthentication, {
        fields: {
            username: {
                validators: {
                    notEmpty: {
                        message: "Please enter username"
                    },
                    stringLength: {
                        min: 4,
                        message: "Username must be more than 4 characters"
                    }
                }
            },
            email: {
                validators: {
                    notEmpty: {
                        message: "Please enter your email"
                    },
                    emailAddress: {
                        message: "Please enter valid email address"
                    }
                }
            },
            // "email-username": {
            //     validators: {
            //         notEmpty: {
            //             message: "Please enter your <b>Email</b> / <b>Username</b>"
            //         },
            //         stringLength: {
            //             min: 4,
            //             message: "Username must be more than <b>4 characters</b>"
            //         },
            //         regexp: {
            //             regexp: /^[a-zA-Z0-9@.]+$/,
            //             message: "<b>Email</b> / <b>Username</b> can only contain <b>Alphabets</b> and <b>Numbers</b>. <b>No spaces</b> or <b>special characters</b> are allowed except <b>'@'</b> and <b>'.'</b>."
            //         }
            //     }
            // }, 
            login: {
                validators: {
                    notEmpty: {
                        message: "Please enter your <b>Email</b> / <b>Username</b>"
                    },
                    stringLength: {
                        min: 4,
                        message: "Username must be more than <b>4 characters</b>"
                    },
                    regexp: {
                        regexp: /^[a-zA-Z0-9@.]+$/,
                        message: "<b>Email</b> / <b>Username</b> can only contain <b>Alphabets</b> and <b>Numbers</b>. <b>No spaces</b> or <b>special characters</b> are allowed except <b>'@'</b> and <b>'.'</b>."
                    }
                }
            },                       
            // password: {
            //     validators: {
            //         notEmpty: {
            //             message: "Please enter your <b>Password</b>"
            //         },
            //         callback: {
            //             message: "Password must be minimum <b>8 characters</b> and must contain at least <b>One Lowercase and Uppercase Alphabet</b>, <b>One Number</b>, and <b>One Special Character</b>",
            //             callback: function(value, validator, $field) {
            //                 var lengthValid = value.length >= 8;
            //                 var patternValid = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/.test(value);
            //                 return lengthValid && patternValid;
            //             }
            //         }
            //     }
            // }, 
            password: {
                validators: {
                    notEmpty: {
                        message: "Please enter your <b>Password</b>"
                    },
                    regexp: {
                        regexp: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
                        message: "Password must contain at least <b>One Lowercase Letter</b>, <b>One Uppercase Letter</b>, <b>One Number</b>, and <b>One Special Character</b>"
                    },
                    stringLength: {
                        min: 8,
                        message: "Password must be at least <b>8 Characters</b>"
                    }
                }
            },                       
            "confirm-password": {
                validators: {
                    notEmpty: {
                        message: "Please confirm password"
                    },
                    identical: {
                        compare: function() {
                            return formAuthentication.querySelector('[name="password"]').value
                        },
                        message: "The password and its confirm are not the same"
                    },
                    stringLength: {
                        min: 6,
                        message: "Password must be more than 6 characters"
                    }
                }
            },
            terms: {
                validators: {
                    notEmpty: {
                        message: "Please agree terms & conditions"
                    }
                }
            }
        },
        plugins: {
            trigger: new FormValidation.plugins.Trigger,
            bootstrap5: new FormValidation.plugins.Bootstrap5({
                eleValidClass: "",
                rowSelector: ".mb-3"
            }),
            submitButton: new FormValidation.plugins.SubmitButton,
            defaultSubmit: new FormValidation.plugins.DefaultSubmit,
            autoFocus: new FormValidation.plugins.AutoFocus
        },
        init: e => {
            e.on("plugins.message.placed", function(e) {
                e.element.parentElement.classList.contains("input-group") && e.element.parentElement.insertAdjacentElement("afterend", e.messageElement)
            })
        }
    }), (t = document.querySelectorAll(".numeral-mask")).length && t.forEach(e => {
        new Cleave(e, {
            numeral: !0
        })
    })
});