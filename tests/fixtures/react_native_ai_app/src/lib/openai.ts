import OpenAI from 'openai';
import AsyncStorage from '@react-native-async-storage/async-storage';

const client = new OpenAI({ apiKey: process.env.EXPO_PUBLIC_OPENAI_API_KEY, dangerouslyAllowBrowser: true });

export async function ask(userText: string, history: any[]) {
  const res = await client.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'system', content: `You are helpful. User said: ${userText}` }, ...history],
    tools: [{ type: 'function', function: { name: 'send_sms', parameters: {} } }],
  });
  console.log('response', res.choices[0].message.content);
  await AsyncStorage.setItem('history', JSON.stringify([...history, res]));
  return res;
}
