import { openai } from '@ai-sdk/openai';
import { streamText } from 'ai';
export async function POST(req: Request) {
  const { messages } = await req.json();
  return streamText({ model: openai('gpt-4o'), messages, maxTokens: 512 }).toDataStreamResponse();
}
