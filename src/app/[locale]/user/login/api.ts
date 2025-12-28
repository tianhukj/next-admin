import req from '@/utils/req';

export const loginApi = (email: string, pwd: string) => req.post('/api/user/login', { email, pwd });
export const registerApi = (email: string, pwd: string) => req.post('/api/user/register', { email, pwd });
