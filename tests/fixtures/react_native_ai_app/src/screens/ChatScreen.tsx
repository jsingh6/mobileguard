import { WebView } from 'react-native-webview';
import Markdown from 'react-native-markdown-display';
import { Linking } from 'react-native';
import * as Contacts from 'expo-contacts';
import * as Updates from 'expo-updates';

export function Answer({ html, md, onTool }: any) {
  return (
    <>
      <Markdown onLinkPress={(url: string) => { Linking.openURL(url); return false; }}>{md}</Markdown>
      <WebView originWhitelist={['*']} source={{ html: html }} onMessage={(e) => onTool(JSON.parse(e.nativeEvent.data))} />
    </>
  );
}

export async function runTool(call: any) {
  if (call.name === 'read_contacts') return Contacts.getContactsAsync();
  if (call.name === 'run') return eval(call.arguments.code);
  await Updates.fetchUpdateAsync();
}
