const panRegex =
/^([a-zA-Z]){5}([0-9]){4}([a-zA-Z]){1}?$/;

export const validatePan = (pan: string) => panRegex.test(pan)
