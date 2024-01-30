// TODO: migrate these function calls to use the shared Address model
export const addressEquals = (address1: string, address2: string): boolean => {
  return address1.toLowerCase() === address2.toLowerCase();
};
