import { parsePhoneNumber } from 'libphonenumber-js'

export const formatPhoneNumber = (phoneNumber: string) => {
  // Custom logic to remove +91 to suit our BE requirement
  if (phoneNumber.startsWith('+91')) {
    return phoneNumber.slice(phoneNumber.length - 10)
  } else {
    return parsePhoneNumber(phoneNumber).formatInternational()
  }
}
