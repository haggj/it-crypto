/**
 * This load the crypto object when running in a browser-like environment.
 * The package.json browser-field substitutes the field accordingly.
 * Details in https://github.com/defunctzombie/package-browser-field-spec
 */
export const cryptoPlatform = window.crypto;
